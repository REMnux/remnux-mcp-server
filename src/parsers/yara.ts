/**
 * Parser for yara-rules output.
 *
 * Deduplicates packer-family rule variants (e.g., 24 PECompact rules → 1 finding with count).
 */

import type { ParsedToolOutput } from "./types.js";

/** Patterns that indicate packer-family rule variants. */
const PACKER_FAMILY_PATTERNS = [
  /^(PECompact)[\s_]?v?\d/i,
  /^(UPX)[\s_]?v?\d/i,
  /^(ASPack)[\s_]?v?\d/i,
  /^(Themida)[\s_]?v?\d/i,
  /^(MPRESS)[\s_]?v?\d/i,
  /^(Armadillo)[\s_]?v?\d/i,
  /^(Petite)[\s_]?v?\d/i,
  /^(FSG)[\s_]?v?\d/i,
  /^(MEW)[\s_]?v?\d/i,
  /^(nspack)[\s_]?v?\d/i,
];

function getPackerFamily(ruleName: string): string | null {
  for (const pattern of PACKER_FAMILY_PATTERNS) {
    const match = ruleName.match(pattern);
    if (match) return match[1];
  }
  return null;
}

export function parseYaraOutput(rawOutput: string): ParsedToolOutput {
  const result: ParsedToolOutput = {
    tool: "yara-rules",
    parsed: false,
    findings: [],
    metadata: {},
    raw: rawOutput,
  };

  const lines = rawOutput.split("\n").filter((l) => l.trim());
  if (lines.length === 0) return result;

  // YARA output format: "RuleName filePath" per line
  const ruleNames: string[] = [];
  for (const line of lines) {
    const match = line.match(/^(\S+)\s+/);
    if (match) ruleNames.push(match[1]);
  }

  if (ruleNames.length === 0) return result;

  // Group by packer family for deduplication
  const packerGroups = new Map<string, string[]>();
  const nonPackerRules: string[] = [];

  for (const name of ruleNames) {
    const family = getPackerFamily(name);
    if (family) {
      const existing = packerGroups.get(family) ?? [];
      existing.push(name);
      packerGroups.set(family, existing);
    } else {
      nonPackerRules.push(name);
    }
  }

  // Emit deduplicated packer findings
  for (const [family, variants] of packerGroups) {
    result.findings.push({
      description: variants.length > 1
        ? `Packer: ${family} (${variants.length} rule variants matched)`
        : `Packer: ${family}`,
      category: "packer",
      severity: "medium",
      evidence: variants.length <= 3 ? variants.join(", ") : `${variants.slice(0, 3).join(", ")} +${variants.length - 3} more`,
    });
  }

  // Emit individual non-packer rules
  for (const name of nonPackerRules) {
    result.findings.push({
      description: `YARA match: ${name}`,
      category: "yara-match",
      severity: "low",
      evidence: name,
    });
  }

  result.metadata.total_rules_matched = ruleNames.length;
  result.metadata.deduplicated_findings = result.findings.length;

  if (result.findings.length > 0) {
    result.parsed = true;
  }

  return result;
}
