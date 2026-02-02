/**
 * Parser for olevba text output.
 *
 * Extracts VBA macro indicators, suspicious keywords, and auto-execute triggers.
 */

import type { ParsedToolOutput } from "./types.js";

/** Keywords indicating suspicious VBA behavior. */
const SUSPICIOUS_PATTERNS: Array<{ pattern: RegExp; category: string; severity: "info" | "low" | "medium" | "high" | "critical" }> = [
  { pattern: /AutoOpen|Document_Open|Auto_Open|Workbook_Open/i, category: "auto-execute", severity: "high" },
  { pattern: /Shell|WScript\.Shell|CreateObject/i, category: "execution", severity: "high" },
  { pattern: /PowerShell|cmd\.exe|command/i, category: "execution", severity: "high" },
  { pattern: /URLDownloadToFile|XMLHTTP|WinHttp/i, category: "download", severity: "high" },
  { pattern: /Environ|GetTempPath|AppData/i, category: "environment", severity: "medium" },
  { pattern: /Chr\(|Asc\(|StrReverse/i, category: "obfuscation", severity: "medium" },
  { pattern: /Base64|Decode|Encode/i, category: "encoding", severity: "medium" },
  { pattern: /RegWrite|RegRead|Registry/i, category: "registry", severity: "medium" },
  { pattern: /FileSystemObject|CopyFile|DeleteFile/i, category: "file-ops", severity: "medium" },
  { pattern: /CallByName|GetProcAddress|VirtualAlloc/i, category: "api-call", severity: "critical" },
];

export function parseOlevbaOutput(rawOutput: string): ParsedToolOutput {
  const result: ParsedToolOutput = {
    tool: "olevba",
    parsed: false,
    findings: [],
    metadata: {},
    raw: rawOutput,
  };

  const lines = rawOutput.split("\n");
  let hasMacros = false;
  let macroCount = 0;
  const notableKeywords: string[] = [];

  // Detect macro presence from olevba summary table
  for (const line of lines) {
    if (/VBA MACRO/i.test(line)) {
      hasMacros = true;
      macroCount++;
    }

    // olevba summary table: "| Type | Keyword | Description |"
    // Keywords can be multi-word (e.g. "Attribute VB_Name"), so capture until next pipe
    const tableMatch = line.match(/^\|\s*Suspicious\s*\|\s*(.+?)\s*\|/i);
    if (tableMatch) {
      notableKeywords.push(tableMatch[1].trim());
    }

    // Also catch "| AutoExec |" and "| IOC |" rows
    const autoExecMatch = line.match(/^\|\s*AutoExec\s*\|\s*(.+?)\s*\|/i);
    if (autoExecMatch) {
      result.findings.push({
        description: `Auto-execute trigger: ${autoExecMatch[1].trim()}`,
        category: "auto-execute",
        severity: "high",
        evidence: line.trim(),
      });
    }

    const iocMatch = line.match(/^\|\s*IOC\s*\|\s*(.+?)\s*\|/i);
    if (iocMatch) {
      result.findings.push({
        description: `IOC detected: ${iocMatch[1].trim()}`,
        category: "ioc",
        severity: "high",
        evidence: line.trim(),
      });
    }
  }

  // Pattern-based detection across full output
  for (const { pattern, category, severity } of SUSPICIOUS_PATTERNS) {
    const matches = rawOutput.match(new RegExp(pattern.source, "gi"));
    if (matches) {
      result.findings.push({
        description: `Notable pattern: ${matches[0]}`,
        category,
        severity,
        evidence: matches.slice(0, 3).join(", "),
      });
    }
  }

  if (hasMacros || result.findings.length > 0) {
    result.parsed = true;
    result.metadata.has_macros = hasMacros;
    result.metadata.macro_count = macroCount;
    result.metadata.notable_keywords = notableKeywords;
  }

  return result;
}
