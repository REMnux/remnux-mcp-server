/**
 * Parser for readelf -h (header) output.
 *
 * Extracts ELF header fields: type, machine, entry point, etc.
 */

import type { ParsedToolOutput } from "./types.js";

export function parseReadelfOutput(rawOutput: string): ParsedToolOutput {
  const result: ParsedToolOutput = {
    tool: "readelf-header",
    parsed: false,
    findings: [],
    metadata: {},
    raw: rawOutput,
  };

  const header: Record<string, string> = {};
  const lines = rawOutput.split("\n");

  for (const line of lines) {
    // readelf -h format: "  Key:                           Value"
    const match = line.match(/^\s*(.+?):\s+(.+)\s*$/);
    if (match) {
      const key = match[1].trim();
      const value = match[2].trim();
      header[key] = value;
    }
  }

  if (Object.keys(header).length > 0) {
    result.parsed = true;
    result.metadata.header = header;

    // Flag interesting attributes
    if (header["Type"]) {
      result.metadata.elf_type = header["Type"];
    }
    if (header["Machine"]) {
      result.metadata.machine = header["Machine"];
    }
    if (header["Entry point address"]) {
      result.metadata.entry_point = header["Entry point address"];
    }

    // Flag unusual entry point (0x0 may indicate shared lib or corrupt binary)
    if (header["Entry point address"] === "0x0") {
      result.findings.push({
        description: "Entry point is 0x0 (shared library or unusual binary)",
        category: "binary-info",
        severity: "info",
        evidence: "Entry point address: 0x0",
      });
    }
  }

  return result;
}
