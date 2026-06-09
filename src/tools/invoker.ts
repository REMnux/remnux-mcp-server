/**
 * Tool Invoker — builds shell commands from ToolDefinition entries.
 *
 * Builds shell commands from ToolDefinition entries,
 * handling all inputStyle variants (positional, flag, stdin).
 */

import type { ToolDefinition } from "./registry.js";

/**
 * Sentinel prefix for per-session output paths. It has no meaning on the host
 * filesystem, so if it ever leaks into model-visible output it cannot be
 * mistaken for a real path the way a literal `/tmp` can. Resolved to the active
 * output directory at execution time by `resolveOutputPath`.
 */
export const OUTPUT_SENTINEL = "%OUTPUT%/";

/**
 * Resolve an output-path argument to the active output directory.
 *
 * Handles the `%OUTPUT%/` sentinel (preferred) and the legacy `/tmp/` prefix.
 * Throws if the sentinel is used without an `outputDir` — fail-safe: never emit
 * an unresolved sentinel, and never fall back to a real host `/tmp` path.
 *
 * Single source of truth for output-path resolution, shared by the command
 * builder, the analyze_file pre-creation step, and run_tool.
 */
export function resolveOutputPath(
  arg: string,
  outputDir: string | undefined,
  toolName: string,
): string {
  if (arg.startsWith(OUTPUT_SENTINEL)) {
    if (!outputDir) {
      throw new Error(
        `outputDir is required for tool ${toolName} but was not provided`,
      );
    }
    return outputDir + "/" + arg.slice(OUTPUT_SENTINEL.length);
  }
  // Legacy: resolve a hardcoded /tmp/ path to outputDir when one is available.
  if (outputDir && arg.startsWith("/tmp/")) {
    return arg.replace("/tmp/", outputDir + "/");
  }
  return arg;
}

/**
 * Escape a value for safe inclusion in a single-quoted shell string.
 * Handles embedded single quotes: file's → file'\''s
 */
function shellEscape(value: string): string {
  return `'${value.replace(/'/g, "'\\''")}'`;
}

/**
 * Assemble the ordered parts of a tool command — command, fixedArgs, the input
 * file (per inputStyle), then suffixArgs. This is the single source of truth
 * for argument ordering, shared by the executable builder and the model-facing
 * invocation template so the two can never drift.
 */
function assembleCommand(
  tool: ToolDefinition,
  fileToken: string,
  resolveArg: (arg: string) => string,
): string {
  const parts: string[] = [tool.command];

  if (tool.fixedArgs) {
    parts.push(...tool.fixedArgs.map(resolveArg));
  }

  switch (tool.inputStyle) {
    case "positional":
      parts.push(fileToken);
      break;
    case "flag":
      parts.push(tool.inputFlag ?? "--input", fileToken);
      break;
    case "stdin":
      parts.push("<", fileToken);
      break;
  }

  if (tool.suffixArgs) {
    parts.push(...tool.suffixArgs.map(resolveArg));
  }

  return parts.join(" ");
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
  return assembleCommand(tool, shellEscape(filePath), (arg) =>
    resolveOutputPath(arg, outputDir, tool.name),
  );
}

/**
 * Build a model-facing invocation template for a tool: the exact command to
 * pass to `run_tool`, with a `<file>` placeholder for the sample and the
 * `%OUTPUT%/` sentinel left intact (run_tool and analyze_file resolve it at
 * execution time).
 *
 * suggest_tools surfaces this so the model runs the real invocation
 * (e.g. `emldump.py <file>`, `vol3 -f <file> windows.pslist`) instead of the
 * internal registry name (e.g. `emldump`, `vol3-pslist`), which is not a
 * runnable command.
 */
export function buildInvocationTemplate(tool: ToolDefinition): string {
  return assembleCommand(tool, "<file>", (arg) => arg);
}
