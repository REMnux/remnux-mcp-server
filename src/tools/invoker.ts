/**
 * Tool Invoker — builds shell commands from ToolDefinition entries.
 *
 * Builds shell commands from ToolDefinition entries,
 * handling all inputStyle variants (positional, flag, stdin).
 */

import type { ToolDefinition } from "./registry.js";

/**
 * Escape a value for safe inclusion in a single-quoted shell string.
 * Handles embedded single quotes: file's → file'\''s
 */
function shellEscape(value: string): string {
  return `'${value.replace(/'/g, "'\\''")}'`;
}

/**
 * Build a shell command string from a tool definition and file path.
 *
 * Examples:
 *   positional: peframe '/path/to/file.exe'
 *   flag:       sometool --input '/path/to/file.exe'
 *   stdin:      sometool < '/path/to/file.exe'
 */
export function buildCommandFromDefinition(
  tool: ToolDefinition,
  filePath: string,
  outputDir?: string,
): string {
  const escaped = shellEscape(filePath);
  const parts: string[] = [tool.command];

  // Replace /tmp/ in args with outputDir to avoid concurrent analysis collisions
  const resolveArg = (arg: string): string => {
    if (outputDir && arg.startsWith("/tmp/")) {
      return arg.replace("/tmp/", outputDir + "/");
    }
    return arg;
  };

  if (tool.fixedArgs) {
    parts.push(...tool.fixedArgs.map(resolveArg));
  }

  switch (tool.inputStyle) {
    case "positional":
      parts.push(escaped);
      break;
    case "flag":
      parts.push(tool.inputFlag ?? "--input", escaped);
      break;
    case "stdin":
      parts.push("<", escaped);
      break;
  }

  if (tool.suffixArgs) {
    parts.push(...tool.suffixArgs.map(resolveArg));
  }

  return parts.join(" ");
}
