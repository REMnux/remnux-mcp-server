/**
 * Parser registry — lookup structured output parsers by tool name.
 *
 * Falls back to passthrough for tools without a dedicated parser.
 */

import type { ParsedToolOutput, ToolOutputParser } from "./types.js";
import { passthroughParser } from "./passthrough.js";
import { parseCapaOutput } from "./capa.js";
import { parseDiecOutput } from "./diec.js";
import { parsePdfidOutput } from "./pdfid.js";
import { parseOlevbaOutput } from "./olevba.js";
import { parsePeframeOutput } from "./peframe.js";
import { parseOleidOutput } from "./oleid.js";
import { parseReadelfOutput } from "./readelf.js";
import { parsePdfParserOutput } from "./pdf-parser.js";
import { parseFlossOutput } from "./floss.js";
import { parseYaraOutput } from "./yara.js";

/** Map of tool name → parser function. */
const PARSERS: Record<string, ToolOutputParser> = {
  "capa-json": parseCapaOutput,
  "diec": parseDiecOutput,
  "pdfid": parsePdfidOutput,
  "pdf-parser": parsePdfParserOutput,
  "olevba": parseOlevbaOutput,
  "peframe": parsePeframeOutput,
  "oleid": parseOleidOutput,
  "readelf-header": parseReadelfOutput,
  "floss": parseFlossOutput,
  "yara-rules": parseYaraOutput,
};

/**
 * Parse tool output using a registered parser, or passthrough if none exists.
 */
export function parseToolOutput(toolName: string, rawOutput: string): ParsedToolOutput {
  const parser = PARSERS[toolName];
  if (parser) {
    return parser(rawOutput);
  }
  return passthroughParser(toolName, rawOutput);
}

/**
 * Check if a dedicated parser exists for the given tool.
 */
export function hasParser(toolName: string): boolean {
  return toolName in PARSERS;
}

export type { ParsedToolOutput, ToolOutputParser, Finding } from "./types.js";
