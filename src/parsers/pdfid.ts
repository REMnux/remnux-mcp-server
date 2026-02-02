/**
 * Parser for pdfid.py text output.
 *
 * Extracts keyword counts (e.g., /JS, /JavaScript, /OpenAction, /AA).
 * Expects text output from `pdfid.py <file>`.
 */

import type { ParsedToolOutput } from "./types.js";

/** Keywords that indicate potentially malicious content. */
const SUSPICIOUS_KEYWORDS = new Set([
  "/JS",
  "/JavaScript",
  "/AA",
  "/OpenAction",
  "/AcroForm",
  "/JBIG2Decode",
  "/RichMedia",
  "/Launch",
  "/EmbeddedFile",
  "/XFA",
  "/URI",
]);

export function parsePdfidOutput(rawOutput: string): ParsedToolOutput {
  const result: ParsedToolOutput = {
    tool: "pdfid",
    parsed: false,
    findings: [],
    metadata: {},
    raw: rawOutput,
  };

  const keywords: Record<string, number> = {};
  const lines = rawOutput.split("\n");

  for (const line of lines) {
    // pdfid output format: " /Keyword            count"
    const match = line.match(/^\s*(\/\w+)\s+(\d+)/);
    if (match) {
      const keyword = match[1];
      const count = parseInt(match[2], 10);
      if (isNaN(count)) continue;
      keywords[keyword] = count;

      if (count > 0 && SUSPICIOUS_KEYWORDS.has(keyword)) {
        result.findings.push({
          description: `Suspicious keyword ${keyword} found (count: ${count})`,
          category: "suspicious-keyword",
          severity: keyword === "/JS" || keyword === "/JavaScript" ? "high" : "medium",
          evidence: line.trim(),
        });
      }
    }
  }

  if (Object.keys(keywords).length > 0) {
    result.parsed = true;
    result.metadata.keywords = keywords;
  }

  return result;
}
