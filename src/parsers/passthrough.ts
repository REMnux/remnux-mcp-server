/**
 * Default passthrough parser — returns raw output with no structured parsing.
 */

import type { ParsedToolOutput } from "./types.js";

export function passthroughParser(toolName: string, rawOutput: string): ParsedToolOutput {
  return {
    tool: toolName,
    parsed: false,
    findings: [],
    metadata: {},
    raw: rawOutput,
  };
}
