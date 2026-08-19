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
import { createHash } from "crypto";

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

/**
 * Split a shell command on unquoted, unescaped single `|` characters (pipe
 * stages). `||` is a control operator, not a pipe, and `|` inside quotes or
 * after a backslash is literal text, so none of those split. This is not a
 * full shell parser; it only needs to find the pipeline's last stage.
 */
function splitPipeline(command: string): string[] {
  const stages: string[] = [];
  let current = "";
  let quote: "'" | '"' | null = null;
  for (let i = 0; i < command.length; i++) {
    const ch = command[i];
    if (quote) {
      current += ch;
      if (ch === "\\" && quote === '"' && i + 1 < command.length) {
        current += command[++i];
      } else if (ch === quote) {
        quote = null;
      }
      continue;
    }
    if (ch === "\\" && i + 1 < command.length) {
      current += ch + command[++i];
      continue;
    }
    if (ch === "'" || ch === '"') {
      quote = ch;
      current += ch;
      continue;
    }
    if (ch === "#" && (i === 0 || /\s/.test(command[i - 1]))) {
      break; // the rest of the line is a shell comment
    }
    if (ch === "|") {
      if (command[i + 1] === "|") {
        current += "||";
        i++;
        continue;
      }
      if (command[i + 1] === "&") i++; // `|&` pipes stderr too; still a pipe
      stages.push(current);
      current = "";
      continue;
    }
    current += ch;
  }
  stages.push(current);
  return stages;
}

/**
 * Detect a `head` or `tail` stage that reads from a pipe (any stage after the
 * first; `tail -n 50 file` with no pipe before it is deliberate paging).
 * Excluded: `tail -f/-F/--follow` (streams rather than limits) and
 * `tail -n +1` (returns every line). Such a stage discards producer output the
 * server would otherwise have returned whole, with exit 0 and no other
 * signal — the model-side mirror of server truncation, and an upstream
 * `head -500 | grep` caps the producer just as a terminal one does. Returns
 * the first such stage's text (whitespace-normalized, trailing redirects and
 * operators dropped, length-capped) and which limiter it is, or undefined.
 */
export function detectPipedLimiter(
  command: string,
): { limiter: "head" | "tail"; stage: string } | undefined {
  const stages = splitPipeline(command);
  for (let n = 1; n < stages.length; n++) {
    // Keep only the command word and its arguments: drop anything after a
    // redirect or control operator that follows the limiter.
    const text = stages[n].trim().split(/\s*(?:\d*[<>]|&&|;)/)[0].trim();
    const words = text.split(/\s+/).filter(Boolean);
    if (words.length === 0) continue;
    const cmd = words[0].replace(/^.*\//, "");
    if (cmd !== "head" && cmd !== "tail") continue;
    if (cmd === "tail") {
      const args = words.slice(1);
      const follows = args.some(
        (w) => w === "--follow" || w.startsWith("--follow=") || /^-[A-Za-z]*[fF][A-Za-z]*$/.test(w),
      );
      if (follows) continue;
      // `tail -n +1` / `tail +1` / `--lines=+1` print from line 1: nothing is dropped
      const fromStart = args.some((w, k) => w === "+1" || w === "--lines=+1" || (w === "-n" && args[k + 1] === "+1"));
      if (fromStart) continue;
    }
    return { limiter: cmd, stage: text.replace(/\s+/g, " ").slice(0, 60) };
  }
  return undefined;
}

// Response budgets (JS string length): 100 KiB of stdout, 50 KiB of stderr.
const STDOUT_CAP_CHARS = 100 * 1024;
const MAX_STDERR_RESPONSE = 50 * 1024;

function limiterAdvisory(l: { limiter: "head" | "tail"; stage: string }): string {
  const part = l.limiter === "head" ? "leading" : "trailing";
  return (
    `PARTIAL: the pipeline stage '${l.stage}' keeps only the ${part} part of its input; anything past that ` +
    `point is discarded with no signal, and a pipeline's exit status is its last stage's, not the producer's. ` +
    `run_tool returns stdout whole up to ${STDOUT_CAP_CHARS.toLocaleString("en-US")} characters and says so when ` +
    `it has to cut, so drop the ${l.limiter} stage, or select by content with grep.`
  );
}

/**
 * Collect every matching command advisory (newline-joined) so a command like
 * `strings x | head` carries both the INCOMPLETE and the PARTIAL guidance.
 */
function getCommandAdvisory(command: string): string | undefined {
  const advisories = ADVISORY_PATTERNS.filter((p) => p.match(command)).map((p) => p.advisory);
  const limiter = detectPipedLimiter(command);
  if (limiter) advisories.push(limiterAdvisory(limiter));
  return advisories.length > 0 ? advisories.join("\n") : undefined;
}

/** Count lines the way `wc -l` would, plus one for a final unterminated line. */
function countLines(text: string): number {
  if (text.length === 0) return 0;
  let n = 0;
  for (let i = 0; i < text.length; i++) if (text.charCodeAt(i) === 10) n++;
  return text.endsWith("\n") ? n : n + 1;
}

/**
 * Deterministic, sanitized filename for the redirect-to-file recovery recipe:
 * derived only from the registry tool name (or the sanitized command word) and
 * a hash of the full command, so re-running the same command maps to the same
 * file and no untrusted text reaches the filename.
 */
function suggestedOutputFilename(fullCommand: string, toolName: string | undefined): string {
  const firstWord = fullCommand.trim().split(/\s/)[0]?.replace(/^.*\//, "") ?? "";
  const base = (toolName ?? firstWord).replace(/[^A-Za-z0-9._-]/g, "_").slice(0, 32) || "cmd";
  const hash = createHash("sha256").update(fullCommand).digest("hex").slice(0, 12);
  return `run_tool-${base}-${hash}.stdout.txt`;
}

/**
 * Per-stream truncation notice. Names the omitted line range with
 * server-computed integers and gives a recovery recipe that can actually reach
 * the tail; `head` is never offered as a remedy (it returns another prefix).
 */
function buildTruncationNotice(args: {
  stdoutTruncated: boolean;
  stderrTruncated: boolean;
  stdoutCapturedLength: number;
  stdoutCapturedLines: number;
  stdoutReturnedLines: number;
  stderrCapturedLength: number;
  outputDirSet: boolean;
  outFile: string;
}): string {
  const parts: string[] = [];
  const fmt = (n: number) => String(n); // raw integers: copy-safe into sed ranges
  const cap = STDOUT_CAP_CHARS.toLocaleString("en-US");
  // Quoted so an output directory with spaces still resolves (substitution is textual).
  const outPath = `'${OUTPUT_SENTINEL}${args.outFile}'`;
  const errPath = `'${OUTPUT_SENTINEL}${args.outFile.replace(/\.stdout\.txt$/, ".stderr.txt")}'`;
  if (args.stdoutTruncated && args.stdoutReturnedLines === 0) {
    // Not even one complete line fits: line ranges cannot help, so offer
    // content and chunking recipes instead. (`cut -c` slices per line, not
    // the stream, so it is not offered.)
    parts.push(
      `stdout: ${fmt(args.stdoutCapturedLines)} line(s) captured (${fmt(args.stdoutCapturedLength)} characters); ` +
      `the first line alone fills the ${cap}-character limit, so line ranges cannot help. Narrow by content ` +
      `(e.g. \`<command> | grep -oE '<pattern>'\`) or chunk it: ` +
      (args.outputDirSet
        ? `re-run with \` > ${outPath}\` appended, then \`fold -w 1000 ${outPath} | sed -n '103,$p'\` ` +
          `(chunks of 1000 characters from character 102001 to the end; repeat with a later start if still cut). `
        : `\`<command> | fold -w 1000 | sed -n '103,$p'\` (chunks of 1000 characters from character 102001; ` +
          `repeat with a later start if still cut). `) +
      "'head' returns another prefix and cannot recover the omitted part.",
    );
  } else if (args.stdoutTruncated) {
    const from = args.stdoutReturnedLines + 1;
    // Open-ended range: the line count describes captured stdout, which the
    // connector trims and caps (10 MiB), so a fixed end could miss the tail.
    const range = `${from},$p`;
    let msg =
      `stdout: ${fmt(args.stdoutCapturedLines)} lines captured (${fmt(args.stdoutCapturedLength)} characters); ` +
      `lines 1-${fmt(args.stdoutReturnedLines)} returned in full, the rest omitted (the cut can fall mid-line, ` +
      `so the range below re-reads the cut line whole). `;
    if (args.outputDirSet) {
      msg +=
        `To read the omitted part: re-run the same command with \` > ${outPath}\` appended ` +
        `(the server resolves %OUTPUT% to the output directory), then run_tool \`sed -n '${range}' ${outPath}\` ` +
        `(grep that file for specifics; download_file fetches '${args.outFile}'). If re-running is cheap, ` +
        `\`<command> | sed -n '${range}'\` does it in one call. `;
    } else {
      msg +=
        `To read the omitted part, re-run as \`<command> | sed -n '${range}'\` (repeat with a later start if that ` +
        `is still over the limit), or narrow by content with grep. `;
    }
    msg += "'head' returns another prefix and cannot recover the omitted tail.";
    parts.push(msg);
  }
  if (args.stderrTruncated) {
    let msg =
      `stderr: ${fmt(args.stderrCapturedLength)} characters captured (after noise filtering), the first ` +
      `${fmt(MAX_STDERR_RESPONSE)} returned` +
      (args.stdoutTruncated ? ". " : "; stdout is complete. ");
    if (args.outputDirSet) {
      msg +=
        `To keep all of stderr, re-run as \`( <command> ) 2> ${errPath}\` (the parentheses matter for a pipeline: ` +
        `a bare 2> covers only its last stage; use \`( <command> ) > ${outPath} 2>&1\` for both streams) and ` +
        `query that file with grep or sed -n.`;
    } else {
      msg += "To see more of it, re-run as `( <command> ) 2>&1 | grep -i error` or with a similar filter.";
    }
    parts.push(msg);
  }
  return parts.join("\n");
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

  const MAX_STDOUT_RESPONSE = STDOUT_CAP_CHARS; // 100KB — fits in LLM context

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

    const fullStdoutLength = stdout.length;
    const stderrCapturedLength = stderr.length; // after noise filtering
    const stdoutTruncated = stdout.length > MAX_STDOUT_RESPONSE;
    const stderrTruncated = stderr.length > MAX_STDERR_RESPONSE;
    const truncated = stdoutTruncated || stderrTruncated;

    // Line accounting only on the (rare) truncated path; the returned stdout
    // stays an exact slice with nothing appended, so a forged marker inside
    // the sample's output cannot masquerade as server metadata.
    let stdoutCapturedLines = 0;
    let stdoutReturnedLines = 0;
    if (stdoutTruncated) {
      stdoutCapturedLines = countLines(stdout);
      stdout = stdout.slice(0, MAX_STDOUT_RESPONSE);
      // complete lines inside the slice; a trailing partial line is re-read by the recipe
      for (let i = 0; i < stdout.length; i++) if (stdout.charCodeAt(i) === 10) stdoutReturnedLines++;
    }
    if (stderrTruncated) {
      stderr = stderr.slice(0, MAX_STDERR_RESPONSE);
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
        truncation_notice: buildTruncationNotice({
          stdoutTruncated,
          stderrTruncated,
          stdoutCapturedLength: fullStdoutLength,
          stdoutCapturedLines,
          stdoutReturnedLines,
          stderrCapturedLength,
          outputDirSet: Boolean(config.outputDir),
          outFile: suggestedOutputFilename(fullCommand, toolName),
        }),
        full_stdout_length: fullStdoutLength, // legacy alias of stdout_captured_length
        stdout_truncated: stdoutTruncated,
        stderr_truncated: stderrTruncated,
        stdout_captured_length: fullStdoutLength,
        stderr_captured_length: stderrCapturedLength,
        ...(stdoutTruncated && {
          stdout_captured_lines: stdoutCapturedLines,
          stdout_returned_lines: stdoutReturnedLines,
        }),
      }),
      ...(findings && { findings, parsed_metadata: parsedMetadata }),
      ...(findings && stdoutTruncated && { findings_scope: "returned_prefix" }),
      ...(findings && !stdoutTruncated && detectPipedLimiter(fullCommand) && { findings_scope: "pipeline_limited" }),
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
