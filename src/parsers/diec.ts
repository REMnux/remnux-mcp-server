/**
 * Parser for Detect It Easy (diec) JSON output.
 *
 * Extracts packer/compiler/linker detections.
 * Expects JSON output from `diec --json <file>`.
 */

import type { ParsedToolOutput, Finding } from "./types.js";

/**
 * Parse diec's JSON, tolerating the informational lines it can prepend to
 * stdout before the JSON body (e.g. "[!] Heuristic scan is disabled ...").
 * Tries the raw output first (clean object/array forms), then falls back to
 * the JSON object between the first '{' and the last '}'. The warning line
 * itself starts with '[', so naive bracket-trimming is not safe.
 */
function extractDiecJson(raw: string) {
  const trimmed = raw.trim();
  try {
    return JSON.parse(trimmed);
  } catch {
    const start = trimmed.indexOf("{");
    const end = trimmed.lastIndexOf("}");
    if (start !== -1 && end > start) {
      return JSON.parse(trimmed.slice(start, end + 1));
    }
    throw new SyntaxError("no JSON object found in diec output");
  }
}

export function parseDiecOutput(rawOutput: string): ParsedToolOutput {
  const result: ParsedToolOutput = {
    tool: "diec",
    parsed: false,
    findings: [],
    metadata: {},
    raw: rawOutput,
  };

  try {
    const data = extractDiecJson(rawOutput);
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
      // filetype is top-level in synthetic output, but per-detect in real
      // `diec --json` output (detects[i].filetype).
      const typed = Array.isArray(detects) ? detects.find((d) => d && d.filetype) : undefined;
      result.metadata.filetype = data.filetype ?? typed?.filetype;
    }
  } catch {
    // JSON parse failed — return unparsed
  }

  return result;
}
