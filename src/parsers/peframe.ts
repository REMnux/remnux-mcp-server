/**
 * Parser for peframe text output.
 *
 * Extracts packer info, suspicious imports/sections, and file metadata.
 */

import type { ParsedToolOutput } from "./types.js";

/** Imports commonly associated with malicious behavior. */
const SUSPICIOUS_IMPORTS = new Set([
  "VirtualAlloc", "VirtualProtect", "WriteProcessMemory", "CreateRemoteThread",
  "NtUnmapViewOfSection", "IsDebuggerPresent", "CheckRemoteDebuggerPresent",
  "GetProcAddress", "LoadLibrary", "URLDownloadToFile", "InternetOpen",
  "WinExec", "ShellExecute", "CreateProcess", "RegSetValueEx",
  "CryptDecrypt", "CryptEncrypt",
]);

export function parsePeframeOutput(rawOutput: string): ParsedToolOutput {
  const result: ParsedToolOutput = {
    tool: "peframe",
    parsed: false,
    findings: [],
    metadata: {},
    raw: rawOutput,
  };

  const lines = rawOutput.split("\n");
  let currentSection = "";

  for (const line of lines) {
    const trimmed = line.trim();
    if (!trimmed) continue;

    // Skip peframe section dividers: ASCII "--- Packer ---" and Unicode "━━━━━━━━"
    if (/^[-━─═]{3,}(\s.*[-━─═]*)?$/.test(trimmed)) continue;

    // Section headers in peframe output
    if (/^(file|hashes|packer|strings|imports|sections|metadata)/i.test(trimmed)) {
      currentSection = trimmed.toLowerCase().replace(/:.*/, "").trim();
      continue;
    }

    // Packer detection — only within the packer section, skip metadata lines
    if (currentSection === "packer") {
      if (trimmed !== "None" && trimmed !== "packer" && !/^features\b/i.test(trimmed)) {
        result.findings.push({
          description: `Packer detected: ${trimmed}`,
          category: "packer",
          severity: "medium",
          evidence: trimmed,
        });
        result.metadata.packer = trimmed;
      }
    }

    // Suspicious imports
    for (const imp of SUSPICIOUS_IMPORTS) {
      if (trimmed.includes(imp)) {
        result.findings.push({
          description: `Notable import: ${imp}`,
          category: "notable-import",
          severity: "medium",
          evidence: trimmed,
        });
      }
    }

    // Suspicious strings (URLs, IPs, paths)
    if (currentSection === "strings" || currentSection === "suspicious") {
      if (/https?:\/\/|\\\\[0-9]|\.exe|\.dll|\.bat|\.ps1/i.test(trimmed)) {
        result.findings.push({
          description: `Notable string: ${trimmed.slice(0, 100)}`,
          category: "notable-string",
          severity: "low",
          evidence: trimmed.slice(0, 200),
        });
      }
    }
  }

  if (result.findings.length > 0) {
    result.parsed = true;
  }

  return result;
}
