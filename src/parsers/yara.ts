/**
 * Parser for YARA scanner output (yara-rules and yara-forge).
 *
 * YARA prints one line per matched rule, `[namespace:]rule [tags] [meta] <scanned path>`,
 * and writes its warnings and errors to stderr. For yara-rules, packer-family rule
 * variants are deduplicated (e.g., 24 PECompact rules → 1 finding with count); for
 * yara-forge, whose rules name malware families, each matched rule is its own finding.
 */

import type { ParsedToolOutput, ParseContext } from "./types.js";

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

/** A YARA rule identifier, optionally namespace-qualified. */
const RULE_NAME = /^(?:[^\s:]+:)?[A-Za-z_][A-Za-z0-9_]*$/;

/** YARA's own diagnostics, which reach the parser when stderr stands in for empty stdout. */
const DIAGNOSTIC = /^(?:warning|error)\b/i;

/**
 * The rules a YARA run matched, in first-seen order.
 *
 * A match line starts with a rule identifier and names the scanned file. When the
 * caller knows that file (`targetPath`), the line must end with it; otherwise it must
 * carry at least one more token. Nothing else counts: not the server's "(no output)"
 * placeholder, not a warning or error line, and not an indented or `-s` detail line.
 */
export function extractYaraRuleMatches(rawOutput: string, targetPath?: string): string[] {
  // Lines are compared trimmed, and connectors trim captured output, so trim the path too.
  const target = targetPath?.trim();
  const rules: string[] = [];
  for (const rawLine of rawOutput.split("\n")) {
    if (/^\s/.test(rawLine)) continue;
    const line = rawLine.trim();
    if (!line || DIAGNOSTIC.test(line)) continue;
    const space = line.search(/\s/);
    if (space === -1) continue;
    const rule = line.slice(0, space);
    if (!RULE_NAME.test(rule)) continue;
    if (target && !line.endsWith(` ${target}`)) continue;
    if (!rules.includes(rule)) rules.push(rule);
  }
  return rules;
}

export function parseYaraOutput(
  rawOutput: string,
  ctx?: ParseContext,
  toolName: "yara-rules" | "yara-forge" = "yara-rules",
): ParsedToolOutput {
  const result: ParsedToolOutput = {
    tool: toolName,
    parsed: false,
    findings: [],
    metadata: {},
    raw: rawOutput,
  };

  const ruleNames = extractYaraRuleMatches(rawOutput, ctx?.targetPath);
  if (ruleNames.length === 0) return result;

  if (toolName === "yara-forge") {
    for (const name of ruleNames) {
      result.findings.push({
        description: `YARA family signature: ${name}`,
        category: "yara-family",
        severity: "medium",
        evidence: name,
      });
    }
  } else {
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
  }

  result.metadata.total_rules_matched = ruleNames.length;
  result.metadata.deduplicated_findings = result.findings.length;
  result.parsed = true;

  return result;
}

/** Parser entry for yara-forge (family-attribution ruleset). */
export const parseYaraForgeOutput = (rawOutput: string, ctx?: ParseContext): ParsedToolOutput =>
  parseYaraOutput(rawOutput, ctx, "yara-forge");
