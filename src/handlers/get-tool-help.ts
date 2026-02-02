import type { HandlerDeps } from "./types.js";
import type { GetToolHelpArgs } from "../schemas/tools.js";
import { formatResponse, formatError } from "../response.js";
import { REMnuxError } from "../errors/remnux-error.js";
import { toREMnuxError } from "../errors/error-mapper.js";

const TOOL_NAME_RE = /^[a-zA-Z0-9][a-zA-Z0-9._-]*$/;

export async function handleGetToolHelp(
  deps: HandlerDeps,
  args: GetToolHelpArgs,
) {
  const startTime = Date.now();
  try {
    const { connector } = deps;
    const tool = args.tool;

    if (!TOOL_NAME_RE.test(tool)) {
      return formatError("get_tool_help", new REMnuxError(
        `Invalid tool name: "${tool}". Use a simple name like 'capa' or 'pdfid.py' (no paths, flags, or shell metacharacters).`,
        "INVALID_INPUT",
        "validation",
        "Provide just the tool name, e.g., 'olevba' not 'olevba -a'",
      ), startTime);
    }

    // Try --help first, fall back to -h
    let output = "";
    let exitCode = 0;

    for (const flag of ["--help", "-h"]) {
      try {
        const result = await connector.execute([tool, flag], { timeout: 10000 });
        const combined = [result.stdout, result.stderr].filter(Boolean).join("\n").trim();
        exitCode = result.exitCode;

        // Detect tool not installed (exit code 127 is the standard shell signal)
        if (result.exitCode === 127) {
          return formatError("get_tool_help", new REMnuxError(
            `Tool '${tool}' not found. It may not be installed on this REMnux system.`,
            "NOT_FOUND",
            "not_found",
            "Use check_tools to see installed tools, or install with apt/pip",
          ), startTime);
        }

        if (combined) {
          output = combined;
          break;
        }
      } catch (error) {
        const msg = error instanceof Error ? error.message : String(error);
        if (/timeout/i.test(msg)) {
          return formatError("get_tool_help", new REMnuxError(
            `Timed out running '${tool} ${flag}'`,
            "COMMAND_TIMEOUT",
            "timeout",
            "The tool may require input or not support help flags",
          ), startTime);
        }
        // Continue to next flag
      }
    }

    if (!output) {
      return formatError("get_tool_help", new REMnuxError(
        `No help output from '${tool}'. The tool may not be installed or may not support --help/-h.`,
        "EMPTY_OUTPUT",
        "tool_failure",
        "Check that the tool is installed with check_tools, or try run_tool with a specific command",
      ), startTime);
    }

    return formatResponse("get_tool_help", {
      tool,
      help: output,
      exit_code: exitCode,
    }, startTime);
  } catch (error) {
    return formatError("get_tool_help", toREMnuxError(error, deps.config.mode), startTime);
  }
}
