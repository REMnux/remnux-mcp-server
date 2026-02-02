/**
 * Parser for FLOSS (FireEye Labs Obfuscated String Solver) output.
 *
 * Sections: FLOSS static strings, FLOSS decoded strings, FLOSS stack strings, FLOSS tight strings.
 * For packed samples: omit static strings, prioritize decoded/stack/tight.
 * For unpacked: cap static strings at top 100.
 */

import type { ParsedToolOutput } from "./types.js";

const SECTION_HEADERS: Record<string, string> = {
  "floss static strings": "static",
  "floss decoded strings": "decoded",
  "floss stack strings": "stack",
  "floss tight strings": "tight",
  "static strings": "static",
  "decoded strings": "decoded",
  "stack strings": "stack",
  "tight strings": "tight",
};

const STATIC_CAP = 100;

export interface FlossParserOptions {
  /** Whether the sample was detected as packed (omits static strings). */
  packed?: boolean;
}

export function parseFlossOutput(
  rawOutput: string,
  options: FlossParserOptions = {},
): ParsedToolOutput {
  const result: ParsedToolOutput = {
    tool: "floss",
    parsed: false,
    findings: [],
    metadata: {},
    raw: rawOutput,
  };

  const sections: Record<string, string[]> = {
    static: [],
    decoded: [],
    stack: [],
    tight: [],
  };

  let currentSection = "";
  const lines = rawOutput.split("\n");

  for (const line of lines) {
    const trimmed = line.trim();

    // Check for section headers (case-insensitive)
    const lower = trimmed.toLowerCase();
    // Match "─── FLOSS DECODED STRINGS ───" or "FLOSS DECODED STRINGS" or just "DECODED STRINGS"
    const stripped = lower.replace(/[─━═\-]/g, "").trim();
    if (SECTION_HEADERS[stripped]) {
      currentSection = SECTION_HEADERS[stripped];
      continue;
    }

    // Skip decorative lines
    if (/^[─━═\-]+$/.test(trimmed)) continue;
    if (!trimmed) continue;

    if (currentSection && sections[currentSection]) {
      sections[currentSection].push(trimmed);
    }
  }

  const counts: Record<string, number> = {};
  for (const [section, strings] of Object.entries(sections)) {
    counts[section] = strings.length;
  }
  result.metadata.string_counts = counts;

  // Build findings — prioritize decoded/stack/tight
  for (const section of ["decoded", "stack", "tight"] as const) {
    if (sections[section].length > 0) {
      result.findings.push({
        description: `${sections[section].length} ${section} strings extracted`,
        category: `floss-${section}`,
        severity: section === "decoded" ? "medium" : "low",
        evidence: sections[section].slice(0, 50).join("\n"),
      });
    }
  }

  // Static strings: omit if packed, cap otherwise
  if (!options.packed && sections.static.length > 0) {
    const capped = sections.static.length > STATIC_CAP;
    result.findings.push({
      description: `${sections.static.length} static strings${capped ? ` (showing first ${STATIC_CAP})` : ""}`,
      category: "floss-static",
      severity: "info",
      evidence: sections.static.slice(0, STATIC_CAP).join("\n"),
    });
  } else if (options.packed && sections.static.length > 0) {
    result.metadata.static_strings_omitted = true;
    result.metadata.static_strings_omitted_reason = "packed sample — static strings unreliable";
  }

  if (result.findings.length > 0) {
    result.parsed = true;
  }

  return result;
}
