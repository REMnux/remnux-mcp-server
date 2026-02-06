import type { HandlerDeps } from "./types.js";
import type { RunToolArgs } from "../schemas/tools.js";
import { validateFilePath, isCommandSafe } from "../security/blocklist.js";
import { formatResponse, formatError } from "../response.js";
import { REMnuxError } from "../errors/remnux-error.js";
import { toREMnuxError } from "../errors/error-mapper.js";
import { parseToolOutput, hasParser } from "../parsers/index.js";
import { toolRegistry } from "../tools/registry.js";
import { filterStderrNoise } from "../utils/stderr-filter.js";

/**
 * Command-specific advisory guidance for suboptimal patterns.
 * Returns advisory text when a better alternative exists.
 */
function getCommandAdvisory(command: string): string | undefined {
  const firstWord = command.trim().split(/\s/)[0];
  // Strip path prefix (/usr/bin/yara → yara) to match commands invoked with full path
  const baseCmd = firstWord.replace(/^.*\//, "");
  // Advise on raw yara but not yara-forge or yara-rules (the good alternatives)
  if (baseCmd === "yara") {
    return (
      "Consider using 'yara-forge' (45+ curated rule sources) or 'yara-rules' " +
      "(capability detection) instead of raw yara. These are run automatically " +
      "by analyze_file and have structured output parsers."
    );
  }
  return undefined;
}

export async function handleRunTool(
  deps: HandlerDeps,
  args: RunToolArgs
) {
  const startTime = Date.now();
  const { connector, config } = deps;

  // Build full command
  let fullCommand = args.command;
  if (args.input_file) {
    // Validate input file path (skip unless --sandbox)
    if (!config.noSandbox) {
      const pathValidation = validateFilePath(args.input_file, config.samplesDir);
      if (!pathValidation.safe) {
        return formatError("run_tool", new REMnuxError(
          pathValidation.error || "Invalid input file path",
          "INVALID_PATH",
          "validation",
          "Use a relative path within the samples directory",
        ), startTime);
      }
    }
    // Append quoted file path to command (single-quotes prevent shell expansion)
    // Escape any single quotes in the path as defense-in-depth (isPathSafe also rejects them)
    const escapedFile = args.input_file.replace(/'/g, "'\\''");
    const resolvedInputFile = (config.mode === "local" && args.input_file.startsWith("/")) ? escapedFile : `${config.samplesDir}/${escapedFile}`;
    fullCommand = `${args.command} '${resolvedInputFile}'`;
  }

  // Security: Validate command against blocklist
  const validation = isCommandSafe(fullCommand);
  if (!validation.safe) {
    return formatError("run_tool", new REMnuxError(
      validation.error || "Command blocked",
      "COMMAND_BLOCKED",
      "security",
      "This command is blocked for security reasons. Use an allowed tool instead.",
    ), startTime);
  }

  const MAX_STDOUT_RESPONSE = 100 * 1024; // 100KB — fits in LLM context
  const MAX_STDERR_RESPONSE = 50 * 1024;

  try {
    const execOptions: { timeout: number; cwd?: string } = {
      timeout: (args.timeout || config.timeout) * 1000,
    };

    // Only set cwd when input_file is provided (file-based analysis)
    if (args.input_file) {
      execOptions.cwd = config.samplesDir;
    }

    const result = await connector.executeShell(fullCommand, execOptions);

    let stdout = result.stdout || "";
    let stderr = result.stderr || "";

    stderr = filterStderrNoise(stderr);

    let truncated = false;
    const fullStdoutLength = stdout.length;

    if (stdout.length > MAX_STDOUT_RESPONSE) {
      stdout = stdout.slice(0, MAX_STDOUT_RESPONSE);
      truncated = true;
    }
    if (stderr.length > MAX_STDERR_RESPONSE) {
      stderr = stderr.slice(0, MAX_STDERR_RESPONSE);
      truncated = true;
    }

    // Auto-parse output if command matches a known tool with a parser
    let findings;
    let parsedMetadata;
    const toolName = detectToolName(fullCommand);
    if (toolName && hasParser(toolName) && stdout) {
      const parsed = parseToolOutput(toolName, stdout);
      if (parsed.parsed) {
        findings = parsed.findings;
        parsedMetadata = parsed.metadata;
      }
    }

    // Check for command-specific advisory guidance
    const advisory = getCommandAdvisory(fullCommand);

    return formatResponse("run_tool", {
      command: fullCommand,
      stdout,
      stderr,
      exit_code: result.exitCode,
      truncated,
      ...(truncated && {
        truncation_notice: "Output exceeded response size limit. Use 'run_tool' with '| head -N' or redirect to a file for full output.",
        full_stdout_length: fullStdoutLength,
      }),
      ...(findings && { findings, parsed_metadata: parsedMetadata }),
      ...(advisory && { advisory }),
    }, startTime);
  } catch (error) {
    return formatError("run_tool", toREMnuxError(error, config.mode), startTime);
  }
}

/**
 * Detect the parser-registered tool name from a command string.
 * Extracts the base command name (strips path and .py suffix),
 * then finds a registry definition whose command matches AND has a parser.
 */
function detectToolName(command: string): string | undefined {
  const firstWord = command.split(/\s/)[0];
  // Strip path prefix (/usr/bin/olevba → olevba) and .py suffix
  const baseCmd = firstWord.replace(/^.*\//, "").replace(/\.py$/, "");

  // Check registry definitions that have a parser
  for (const def of toolRegistry.all()) {
    if (def.command === baseCmd && hasParser(def.name)) {
      return def.name;
    }
  }
  // Direct parser name match (e.g. command name IS the parser key)
  if (hasParser(baseCmd)) return baseCmd;
  return undefined;
}
