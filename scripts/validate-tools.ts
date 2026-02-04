#!/usr/bin/env bun
/**
 * Validates definitions.ts against the catalog from salt-states.
 *
 * The catalog (data/tools-index.json) is synced from REMnux salt-states via
 * update-docs.py --sync-mcp. This script ensures that all tools defined in
 * definitions.ts actually exist in the REMnux distro.
 *
 * Run: bun run scripts/validate-tools.ts
 */

import { readFileSync } from "fs";
import { resolve, dirname } from "path";
import { fileURLToPath } from "url";

// Get project root
const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const projectRoot = resolve(__dirname, "..");

// Load tool definitions dynamically to avoid build dependency
// eslint-disable-next-line @typescript-eslint/no-require-imports
const { TOOL_DEFINITIONS } = await import(resolve(projectRoot, "src/tools/definitions.js"));

// Load catalog
const catalogPath = resolve(projectRoot, "data/tools-index.json");
const catalogRaw = readFileSync(catalogPath, "utf-8");
const catalog = JSON.parse(catalogRaw) as { tools: Array<{ command: string; name: string }> };

// Build set of catalog commands (lowercase for case-insensitive matching)
const catalogCommands = new Set(catalog.tools.map((t) => t.command.toLowerCase()));

// Also check for tool names in catalog that might be the actual executable
// e.g., catalog might have "1768" but the command is actually "1768.py"
const catalogNames = new Set(catalog.tools.map((t) => t.name.toLowerCase()));

// Known aliases: executable command -> catalog package name
// The catalog uses package names while definitions.ts uses actual executables
const KNOWN_ALIASES: Record<string, string> = {
  // Detect-It-Easy
  diec: "detect-it-easy",
  // oletools package provides multiple executables
  oleid: "oletools",
  olevba: "oletools",
  rtfobj: "oletools",
  // Volatility 3
  vol3: "volatility-framework",
  // Qiling framework
  qltool: "qiling",
  // ILSpy decompiler
  ilspycmd: "ilspy",
  // Standard system utilities (not in REMnux catalog but always present)
  readelf: "_system",
  strings: "_system",
  file: "_system",
  // PDF tools from origami package
  pdfcop: "origamindee",
  pdfextract: "origamindee",
  pdfdecompress: "origamindee",
  // XLM deobfuscator
  xlmdeobfuscator: "xlmmacrodeobfuscator",
  // JavaScript beautifier
  "js-beautify": "js-beautifier",
  // Python decompiler (Decompyle++)
  pycdc: "decompyle",
  // PE scanner from pev/readpe
  pescan: "readpe-formerly-pev",
  // dotnetfile
  "dotnetfile_dump.py": "dotnetfile",
  // Wine-based shellcode tracer
  tracesc: "wine",
};

// Validate each definition
const missing: string[] = [];

for (const def of TOOL_DEFINITIONS) {
  const cmd = def.command.toLowerCase();
  const cmdBase = cmd.replace(/\.(py|sh|rb|pl)$/i, ""); // Strip script extension

  // Check known aliases first
  const alias = KNOWN_ALIASES[cmd] || KNOWN_ALIASES[cmdBase];
  if (alias === "_system") {
    // System utility, always available
    continue;
  }

  // Check if command exists in catalog (by command field or by name field)
  const inCatalog =
    catalogCommands.has(cmd) ||
    catalogCommands.has(cmdBase) ||
    catalogNames.has(cmd) ||
    catalogNames.has(cmdBase) ||
    // Check alias mapping
    (alias && catalogCommands.has(alias)) ||
    // Some tools have long slugified names in the catalog
    Array.from(catalogCommands).some((c) => c.includes(cmdBase));

  if (!inCatalog) {
    missing.push(`${def.name} (command: ${def.command})`);
  }
}

// Report results
if (missing.length > 0) {
  console.error("❌ Tools in definitions.ts not found in REMnux catalog:");
  missing.forEach((m) => console.error(`   - ${m}`));
  console.error("\nActions:");
  console.error("  1. Run 'update-docs.py --sync-mcp' to refresh the catalog");
  console.error("  2. If tool was removed from REMnux, remove from definitions.ts");
  console.error("  3. If tool is new to REMnux, add it to salt-states first");
  process.exit(1);
}

console.log(`✅ All ${TOOL_DEFINITIONS.length} tool definitions validated against catalog`);
