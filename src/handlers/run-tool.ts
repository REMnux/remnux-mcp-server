import type { HandlerDeps } from "./types.js";
import type { RunToolArgs } from "../schemas/tools.js";
import { validateFilePath, isCommandSafe } from "../security/blocklist.js";
import { formatResponse, formatError } from "../response.js";
import { REMnuxError } from "../errors/remnux-error.js";
import { toREMnuxError } from "../errors/error-mapper.js";
import { parseToolOutput, hasParser } from "../parsers/index.js";
import { toolRegistry } from "../tools/registry.js";
import { filterStderrNoise } from "../utils/stderr-filter.js";
import { OUTPUT_SENTINEL } from "../tools/invoker.js";

/**
 * Pre-execution warning patterns for discouraged commands.
 * These block execution and require acknowledgment to proceed.
 */
interface DiscouragedPattern {
  pattern: RegExp;
  warning: string;
  suggestion: string;
}

const DISCOURAGED_PATTERNS: DiscouragedPattern[] = [
  {
    pattern: /^yara\s/,
    warning: "Raw yara command detected.",
    suggestion:
      "Use yara-forge (45+ curated rule sources) or yara-rules (capability detection) instead. " +
      "These are pre-configured and have structured output parsers. " +
      "If you need raw yara with custom rules, re-run with --acknowledge-raw flag.",
  },
];

/**
 * Non-blocking advisory patterns for suboptimal commands.
 * Returns guidance in response WITHOUT blocking execution.
 */
interface AdvisoryPattern {
  match: (command: string) => boolean;
  advisory: string;
}

const ADVISORY_PATTERNS: AdvisoryPattern[] = [
  {
    match: (cmd) => {
      const firstWord = cmd.trim().split(/\s/)[0].replace(/^.*\//, "");
      if (firstWord !== "strings") return false;
      // Don't advise if already extracting Unicode (-e with encoding specifier)
      // -el = little-endian 16-bit, -eb = big-endian 16-bit, -eL/-eB = 32-bit
      if (/-e[lbLB]/.test(cmd)) return false;
      return true;
    },
    advisory:
      "INCOMPLETE: 'strings' extracts ASCII only. To capture Unicode strings: " +
      "PE files → use 'pestr' instead (extracts both ASCII+Unicode with section context). " +
      "Other files → also run 'strings -el <file>' for Unicode (little-endian 16-bit).",
  },
];

function getCommandAdvisory(command: string): string | undefined {
  const matched = ADVISORY_PATTERNS.find((p) => p.match(command));
  return matched?.advisory;
}

/**
 * Output-conditioned advisories: fire on failure evidence in the tool's
 * output rather than on command shape. Non-blocking — attached to the
 * response as `output_advisory` after execution. Use for tools whose exit
 * code cannot be trusted to reflect failure.
 */
interface OutputAdvisoryContext {
  command: string;
  stdout: string;
  stderr: string;
  exitCode: number;
}

interface OutputAdvisoryPattern {
  matches: (ctx: OutputAdvisoryContext) => boolean;
  advisory: string;
}

// An actual js_unshroud capture invocation: the executable (wrapper, full or
// quoted path, or raw js_unshroud-linux-x64 binary) followed by the `run`
// subcommand. Requiring `run` keeps textual mentions (grep js_unshroud ...)
// and the display-free subcommands (analyze/query/correlate) from matching.
const JS_UNSHROUD_RUN_CMD = /(^|[/\s'"])js_unshroud(-linux-x64)?['"]?\s+run(\s|$)/;

// js_unshroud's own monitoring-error banner (line-anchored, so a negated
// mention like "No error during monitoring" cannot match) plus Playwright's
// standard launch-failure phrasings. The command gate keeps these patterns
// from firing on other tools' output.
const JS_UNSHROUD_FAILURE_OUTPUT =
  /(^|\n)\s*Error during monitoring|browser has been closed|browserType\.launch|Failed to launch (chromium|browser)|Missing X server|missing dependencies to run browsers/i;

const OUTPUT_ADVISORY_PATTERNS: OutputAdvisoryPattern[] = [
  {
    // js_unshroud can exit 0 even when its Playwright browser fails to launch
    // or dies mid-capture, so a successful-looking run may have recorded
    // little or nothing.
    matches: ({ command, stdout, stderr }) =>
      JS_UNSHROUD_RUN_CMD.test(command.trim()) &&
      (JS_UNSHROUD_FAILURE_OUTPUT.test(stdout) ||
        JS_UNSHROUD_FAILURE_OUTPUT.test(stderr)),
    advisory:
      "POSSIBLE CAPTURE FAILURE despite the exit code: js_unshroud reported a browser " +
      "or monitoring error, so the events file may be empty or incomplete — verify it " +
      "has events (e.g. 'wc -l <out.jsonl>') before relying on the capture. If the " +
      "browser failed to launch on a headless system, the usual cause is a missing " +
      "display: current REMnux versions start a virtual display automatically via the " +
      "js_unshroud wrapper; on older installs re-run as 'xvfb-run -a js_unshroud run " +
      "...' (install xvfb if absent) or refresh the system with 'remnux install'.",
  },
];

/**
 * Scan the pre-truncation, pre-filter output so the failure signal cannot be
 * cut off by response budgets or stderr noise filtering. Collects every
 * matching advisory rather than stopping at the first.
 */
function getOutputAdvisory(ctx: OutputAdvisoryContext): string | undefined {
  const matched = OUTPUT_ADVISORY_PATTERNS.filter((p) => p.matches(ctx));
  return matched.length > 0
    ? matched.map((p) => p.advisory).join("\n")
    : undefined;
}

/**
 * Check if a command matches a discouraged pattern.
 * Returns the pattern if matched, undefined otherwise.
 */
function checkDiscouragedPattern(
  command: string
): DiscouragedPattern | undefined {
  const firstWord = command.trim().split(/\s/)[0];
  // Strip path prefix (/usr/bin/yara → yara) to match commands invoked with full path
  const baseCmd = firstWord.replace(/^.*\//, "");
  // Append space to baseCmd to match pattern (ensures we match "yara " not "yara-forge ")
  return DISCOURAGED_PATTERNS.find((p) => p.pattern.test(baseCmd + " "));
}


export async function handleRunTool(
  deps: HandlerDeps,
  args: RunToolArgs
) {
  const startTime = Date.now();
  const { connector, config } = deps;

  // Resolve a bare registry name to its real command for the ".py" case
  // (e.g. "emldump" → "emldump.py"). suggest_tools surfaces full invocations,
  // but a model may still type the bare name; the ".py" rewrite is the only
  // zero-false-positive resolution. Aliases (a different binary, e.g.
  // "vol3-pslist" → "vol3") are deliberately left alone — they pass through and
  // fail naturally rather than risk shadowing a real command that shares a name.
  // Normalize leading whitespace so a pasted " emldump …" still resolves.
  let command = args.command.replace(/^\s+/, "");
  const firstToken = command.split(/\s/)[0];
  const def = toolRegistry.get(firstToken);
  if (def && def.command === `${firstToken}.py`) {
    command = def.command + command.slice(firstToken.length);
  }

  // Resolve the %OUTPUT% sentinel on the model-supplied command BEFORE the
  // sample path is appended, so a filename that contains the sentinel substring
  // is never rewritten. Done before the blocklist so security sees the real command.
  if (config.outputDir && command.includes(OUTPUT_SENTINEL)) {
    command = command.split(OUTPUT_SENTINEL).join(`${config.outputDir}/`);
  }

  // Build full command
  let fullCommand = command;
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
    fullCommand = `${command} '${resolvedInputFile}'`;
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

  // Check for discouraged patterns BEFORE execution (unless acknowledged)
  // Use regex to ensure --acknowledge-raw is a flag, not part of a filename
  const hasAcknowledge = /(?:^|\s)--acknowledge-raw(?:\s|$)/.test(args.command);
  if (!hasAcknowledge) {
    const discouraged = checkDiscouragedPattern(fullCommand);
    if (discouraged) {
      return formatResponse(
        "run_tool",
        {
          warning: discouraged.warning,
          suggestion: discouraged.suggestion,
          command_blocked: true,
          note: "Command was NOT executed. Use suggested alternatives or add --acknowledge-raw to proceed.",
        },
        startTime
      );
    }
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

    // Check for advisory (non-blocking guidance)
    const advisory = getCommandAdvisory(fullCommand);

    // Output-conditioned advisory (tools that exit 0 on failure); scans the
    // raw output, not the truncated/filtered copy sent in the response
    const outputAdvisory = getOutputAdvisory({
      command: fullCommand,
      stdout: result.stdout ?? "",
      stderr: result.stderr ?? "",
      exitCode: result.exitCode,
    });

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
      ...(outputAdvisory && { output_advisory: outputAdvisory }),
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
