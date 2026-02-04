/**
 * Parser for CAPA JSON output.
 *
 * Extracts capabilities and their associated ATT&CK techniques.
 * Expects JSON output from `capa -j <file>`.
 */

import type { ParsedToolOutput, Finding } from "./types.js";

export function parseCapaOutput(rawOutput: string): ParsedToolOutput {
  const result: ParsedToolOutput = {
    tool: "capa",
    parsed: false,
    findings: [],
    metadata: {},
    raw: rawOutput,
  };

  try {
    const data = JSON.parse(rawOutput);
    result.parsed = true;

    // Extract rules/capabilities
    const rules = data.rules;
    if (rules && typeof rules === "object" && !Array.isArray(rules)) {
      for (const [name, rule] of Object.entries(rules)) {
        if (!rule || typeof rule !== "object") continue;
        const r = rule as Record<string, unknown>;
        const meta = r.meta;
        const finding: Finding = {
          description: name,
          category: "capability",
          severity: "info",
        };

        // Extract ATT&CK info if present — validate array structure
        if (meta && typeof meta === "object" && !Array.isArray(meta)) {
          const m = meta as Record<string, unknown>;
          if (Array.isArray(m.attack) && m.attack.length > 0) {
            finding.evidence = m.attack
              .filter((a): a is Record<string, string> => a && typeof a === "object")
              .map((a) => `${a.technique ?? "?"} (${a.id ?? "?"})`)
              .join(", ");
          }
        }

        result.findings.push(finding);
      }
    }

    // Extract metadata
    if (data.meta && typeof data.meta === "object") {
      result.metadata.sample = data.meta.sample;
      result.metadata.analysis = data.meta.analysis;
    }

    // Provide helpful context when no capabilities are found
    if (result.findings.length === 0) {
      result.metadata.no_findings_reason =
        "No capabilities identified. This may occur when: " +
        "(1) the file is packed/obfuscated and capa cannot analyze the unpacked code, " +
        "(2) the file is a stub/loader with minimal functionality, " +
        "(3) the file's behaviors don't match capa's rule set, or " +
        "(4) the file format isn't fully supported. " +
        "Consider: running a packer detector first (diec, yara), " +
        "unpacking the sample, or using complementary tools like strings/floss.";
    }
  } catch {
    // JSON parse failed — return unparsed
  }

  return result;
}
