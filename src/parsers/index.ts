/**
 * Parser registry — lookup structured output parsers by tool name.
 *
 * Falls back to passthrough for tools without a dedicated parser.
 */

import type { ParsedToolOutput, ToolOutputParser, ParseContext } from "./types.js";
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
import { parseYaraOutput, parseYaraForgeOutput } from "./yara.js";

/** Map of tool name → parser function. */
const PARSERS: Record<string, ToolOutputParser> = {
  "capa": parseCapaOutput,
  "diec": parseDiecOutput,
  "pdfid": parsePdfidOutput,
  "pdf-parser": parsePdfParserOutput,
  "olevba": parseOlevbaOutput,
  "peframe": parsePeframeOutput,
  "oleid": parseOleidOutput,
  "readelf-header": parseReadelfOutput,
  // parseFlossOutput's second parameter is its own options object, not a ParseContext.
  "floss": (rawOutput) => parseFlossOutput(rawOutput),
  "yara-rules": parseYaraOutput,
  "yara-forge": parseYaraForgeOutput,
};

/**
 * Parse tool output using a registered parser, or passthrough if none exists.
 */
export function parseToolOutput(
  toolName: string,
  rawOutput: string,
  ctx?: ParseContext,
): ParsedToolOutput {
  const parser = PARSERS[toolName];
  if (parser) {
    return parser(rawOutput, ctx);
  }
  return passthroughParser(toolName, rawOutput);
}

/**
 * Check if a dedicated parser exists for the given tool.
 */
export function hasParser(toolName: string): boolean {
  return toolName in PARSERS;
}

export type { ParsedToolOutput, ToolOutputParser, ParseContext, Finding } from "./types.js";
