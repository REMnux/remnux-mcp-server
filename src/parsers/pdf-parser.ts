/**
 * Parser for pdf-parser.py --stats output.
 *
 * Extracts keyword counts with object IDs from the "Search keywords" section,
 * and structural summary lines (e.g., "Indirect object: 49").
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

interface KeywordEntry {
  count: number;
  objects: number[];
}

export function parsePdfParserOutput(rawOutput: string): ParsedToolOutput {
  const result: ParsedToolOutput = {
    tool: "pdf-parser",
    parsed: false,
    findings: [],
    metadata: {},
    raw: rawOutput,
  };

  const keywords: Record<string, KeywordEntry> = {};
  const structure: Record<string, number> = {};
  const lines = rawOutput.split("\n");

  for (const line of lines) {
    // Keyword line: " /URI 13: 10, 17, 18, ..."
    const kwMatch = line.match(/^\s*(\/\w+)\s+(\d+):\s*([\d,\s]+)/);
    if (kwMatch) {
      const keyword = kwMatch[1];
      const count = parseInt(kwMatch[2], 10);
      if (isNaN(count)) continue;
      const objects = kwMatch[3]
        .split(",")
        .map((s) => parseInt(s.trim(), 10))
        .filter((n) => !isNaN(n));

      keywords[keyword] = { count, objects };

      if (count > 0 && SUSPICIOUS_KEYWORDS.has(keyword)) {
        result.findings.push({
          description: `Notable keyword ${keyword} found (count: ${count})`,
          category: "notable-keyword",
          severity: keyword === "/JS" || keyword === "/JavaScript" ? "high" : "medium",
          evidence: line.trim(),
        });
      }
      continue;
    }

    // Structure line: "Comment: 5" or "Indirect object: 49"
    const structMatch = line.match(/^\s*([A-Za-z][A-Za-z ]*\w):\s+(\d+)\s*$/);
    if (structMatch) {
      const label = structMatch[1];
      const value = parseInt(structMatch[2], 10);
      if (!isNaN(value)) {
        structure[label] = value;
      }
    }
  }

  if (Object.keys(keywords).length > 0 || Object.keys(structure).length > 0) {
    result.parsed = true;
  }
  if (Object.keys(keywords).length > 0) {
    result.metadata.keywords = keywords;
  }
  if (Object.keys(structure).length > 0) {
    result.metadata.structure = structure;
  }

  return result;
}
