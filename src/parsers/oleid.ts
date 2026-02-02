/**
 * Parser for oleid text output.
 *
 * Extracts OLE risk indicators (macros, encryption, external links, etc.).
 */

import type { ParsedToolOutput } from "./types.js";

/** Risk levels mapped to finding severities. */
const RISK_SEVERITY: Record<string, "info" | "low" | "medium" | "high"> = {
  "No": "info",
  "no": "info",
  "False": "info",
  "false": "info",
  "Yes": "high",
  "yes": "high",
  "True": "high",
  "true": "high",
  "RISK": "high",
  "WARNING": "medium",
  "OK": "info",
};

export function parseOleidOutput(rawOutput: string): ParsedToolOutput {
  const result: ParsedToolOutput = {
    tool: "oleid",
    parsed: false,
    findings: [],
    metadata: {},
    raw: rawOutput,
  };

  const indicators: Record<string, string> = {};
  const lines = rawOutput.split("\n");

  for (const line of lines) {
    // oleid output format varies but commonly:
    // "Indicator                Value"
    // Or table format: "| indicator | value | risk |"
    const tableMatch = line.match(/^\|\s*(.+?)\s*\|\s*(.+?)\s*\|\s*(.+?)\s*\|/);
    if (tableMatch) {
      const [, indicator, value, risk] = tableMatch;
      if (indicator.includes("---") || indicator.toLowerCase() === "indicator") continue;

      indicators[indicator.trim()] = value.trim();
      const riskTrimmed = risk.trim();

      if (riskTrimmed !== "none" && riskTrimmed !== "-" && riskTrimmed.toLowerCase() !== "ok") {
        const severity = RISK_SEVERITY[riskTrimmed] ?? "medium";
        if (severity !== "info") {
          result.findings.push({
            description: `${indicator.trim()}: ${value.trim()}`,
            category: "ole-indicator",
            severity,
            evidence: line.trim(),
          });
        }
      }
      continue;
    }

    // Alternative format: "indicator : value"
    // Only match lines that look like oleid indicators (short key, not error/path lines)
    const kvMatch = line.match(/^\s{0,4}(\w[\w\s]{1,30}?)\s*:\s*(\S.*?)\s*$/);
    if (kvMatch && !line.includes("Error") && !line.includes("/")) {
      const [, key, value] = kvMatch;
      const keyLower = key.trim().toLowerCase();
      indicators[key.trim()] = value.trim();

      // Flag key risk indicators
      if ((keyLower.includes("macro") || keyLower.includes("vba")) && /yes|true/i.test(value)) {
        result.findings.push({
          description: `VBA Macros present: ${value.trim()}`,
          category: "macro",
          severity: "high",
          evidence: line.trim(),
        });
      }
      if (keyLower.includes("encrypt") && /yes|true/i.test(value)) {
        result.findings.push({
          description: `Encryption detected: ${value.trim()}`,
          category: "encryption",
          severity: "medium",
          evidence: line.trim(),
        });
      }
      if (keyLower.includes("external") && /yes|true/i.test(value)) {
        result.findings.push({
          description: `External relationships: ${value.trim()}`,
          category: "external-link",
          severity: "high",
          evidence: line.trim(),
        });
      }
    }
  }

  if (Object.keys(indicators).length > 0) {
    result.parsed = true;
    result.metadata.indicators = indicators;
  }

  return result;
}
