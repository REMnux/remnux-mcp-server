/**
 * Parser for Detect It Easy (diec) JSON output.
 *
 * Extracts packer/compiler/linker detections.
 * Expects JSON output from `diec --json <file>`.
 */

import type { ParsedToolOutput, Finding } from "./types.js";

export function parseDiecOutput(rawOutput: string): ParsedToolOutput {
  const result: ParsedToolOutput = {
    tool: "diec",
    parsed: false,
    findings: [],
    metadata: {},
    raw: rawOutput,
  };

  try {
    const data = JSON.parse(rawOutput);
    result.parsed = true;

    // diec JSON has a "detects" array
    const detects = Array.isArray(data) ? data : data?.detects;
    if (Array.isArray(detects)) {
      for (const detect of detects) {
        if (!detect || typeof detect !== "object") continue;
        const values = detect.values;
        if (Array.isArray(values)) {
          for (const v of values) {
            if (!v || typeof v !== "object") continue;
            const vType = typeof v.type === "string" ? v.type : "detection";
            const vName = typeof v.name === "string" ? v.name : "unknown";
            const finding: Finding = {
              description: `${vType}: ${vName}`,
              category: vType.toLowerCase(),
              severity: "info",
            };
            if (typeof v.version === "string") {
              finding.evidence = `version: ${v.version}`;
            }
            result.findings.push(finding);
          }
        }
      }
    }

    if (data && typeof data === "object" && !Array.isArray(data)) {
      result.metadata.filetype = data.filetype;
    }
  } catch {
    // JSON parse failed — return unparsed
  }

  return result;
}
