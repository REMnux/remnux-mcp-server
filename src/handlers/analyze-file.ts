import type { HandlerDeps } from "./types.js";
import type { AnalyzeFileArgs } from "../schemas/tools.js";
import { validateFilePath } from "../security/blocklist.js";
import { matchFileType, CATEGORY_TAG_MAP } from "../file-type-mappings.js";
import type { DepthTier } from "../file-type-mappings.js";
import { toolRegistry } from "../tools/registry.js";
import { buildCommandFromDefinition } from "../tools/invoker.js";
import { parseToolOutput } from "../parsers/index.js";
import type { Finding } from "../parsers/types.js";
import { formatResponse, formatError } from "../response.js";
import { REMnuxError } from "../errors/remnux-error.js";
import { toREMnuxError } from "../errors/error-mapper.js";
import { extractIOCs } from "../ioc/extractor.js";

interface ToolRun {
  name: string;
  command: string;
  output: string;
  exit_code: number;
  truncated?: boolean;
  full_output_length?: number;
  findings?: Finding[];
  metadata?: Record<string, unknown>;
}
interface ToolFailed { name: string; command: string; error: string }
interface ToolSkipped { name: string; command: string; reason: string }

const DEFAULT_OUTPUT_BUDGET = 80 * 1024; // 80KB default
const TOTAL_RESPONSE_BUDGET = 200 * 1024; // 200KB total across all tools

/** Per-tool output budgets — tools known to produce large output get tighter limits. */
const TOOL_OUTPUT_BUDGETS: Record<string, number> = {
  floss: 20 * 1024,
  ilspycmd: 15 * 1024,
  rtfdump: 10 * 1024,
  olevba: 30 * 1024,
  oledump: 20 * 1024,
  exiftool: 10 * 1024,
  zipdump: 15 * 1024,
};

export async function handleAnalyzeFile(
  deps: HandlerDeps,
  args: AnalyzeFileArgs
) {
  const startTime = Date.now();
  try {
  const { connector, config } = deps;
  const depth = (args.depth ?? "standard") as DepthTier;

  // Validate file path (skip unless --sandbox)
  if (!config.noSandbox) {
    const validation = validateFilePath(args.file, config.samplesDir);
    if (!validation.safe) {
      return formatError("analyze_file", new REMnuxError(
        validation.error || "Invalid file path",
        "INVALID_PATH",
        "validation",
        "Use a relative path within the samples directory",
      ), startTime);
    }
  }

  const filePath = `${config.samplesDir}/${args.file}`;
  const perToolTimeout = (args.timeout_per_tool || 60) * 1000;

  // Step 1: Detect file type
  let fileOutput: string;
  try {
    const result = await connector.execute(["file", filePath], { timeout: 30000 });
    fileOutput = result.stdout?.trim() || "";
    if (!fileOutput) {
      return formatError("analyze_file", new REMnuxError(
        "Could not determine file type (empty `file` output)",
        "EMPTY_OUTPUT",
        "tool_failure",
        "Check that the file exists and is readable",
      ), startTime);
    }
  } catch (error) {
    const msg = `Error running file command: ${error instanceof Error ? error.message : "Unknown error"}`;
    return formatError("analyze_file", new REMnuxError(
      msg,
      "EMPTY_OUTPUT",
      "tool_failure",
      "Check that the file exists and is readable",
    ), startTime);
  }

  // Step 2: Match to category and get tools from registry by tag + depth
  const category = matchFileType(fileOutput, args.file);
  const tag = CATEGORY_TAG_MAP[category.name] ?? "fallback";
  const tools = toolRegistry.byTagAndTier(tag, depth);

  const toolsRun: ToolRun[] = [];
  const toolsFailed: ToolFailed[] = [];
  const toolsSkipped: ToolSkipped[] = [];
  let totalOutputSize = 0;

  // Step 3: Run each tool
  for (const tool of tools) {
    const cmd = buildCommandFromDefinition(tool, filePath);
    // Use the greater of user-specified timeout and tool's own timeout
    const effectiveTimeout = Math.max(perToolTimeout, (tool.timeout ?? 60) * 1000);

    try {
      const result = await connector.executeShell(cmd, {
        timeout: effectiveTimeout,
        cwd: config.samplesDir,
      });

      let stderr = result.stderr || "";
      // Filter Volatility 3 progress bar noise from stderr
      stderr = stderr.replace(/^Progress:\s+[\d.]+\s+.*$/gm, "").trim();
      // Detect missing tools by exit code or error messages
      if (result.exitCode === 127 || stderr.includes("not found") || stderr.includes("No such file or directory")) {
        toolsSkipped.push({ name: tool.name, command: cmd, reason: "Tool not installed" });
        continue;
      }

      let output = result.stdout || stderr || "(no output)";
      const fullLen = output.length;
      // Per-tool budget, further reduced if approaching total response budget
      const remainingBudget = Math.max(5 * 1024, TOTAL_RESPONSE_BUDGET - totalOutputSize);
      const budget = Math.min(TOOL_OUTPUT_BUDGETS[tool.name] ?? DEFAULT_OUTPUT_BUDGET, remainingBudget);
      const outputTruncated = output.length > budget;
      let savedOutputFile: string | undefined;
      if (outputTruncated) {
        // Save full output to output dir for later retrieval
        const safeFile = args.file.replace(/[^a-zA-Z0-9._-]/g, "_");
        const outFilename = `${tool.name}-${safeFile}.txt`;
        try {
          const outPath = `${config.outputDir}/${outFilename}`;
          await connector.writeFile(outPath, Buffer.from(output, "utf-8"));
          savedOutputFile = outFilename;
        } catch {
          // Non-fatal: truncation hint won't include file reference
        }
        output = output.slice(0, budget) +
          `\n\n[Truncated at ${Math.round(budget / 1024)}KB of ${Math.round(fullLen / 1024)}KB total` +
          (savedOutputFile ? `. Full output: output/${savedOutputFile} — use download_file to retrieve]` : "]");
      }

      totalOutputSize += output.length;

      const parsed = parseToolOutput(tool.name, output);

      // capa exit code 14 = packed file detected
      const extraMetadata: Record<string, unknown> = {};
      if ((tool.name === "capa" || tool.name === "capa-json") && result.exitCode === 14) {
        extraMetadata.analyst_note = "capa detected a packed file — capabilities analysis may be incomplete. Consider unpacking first.";
      }

      toolsRun.push({
        name: tool.name,
        command: cmd,
        output,
        exit_code: result.exitCode,
        ...(outputTruncated && { truncated: true, full_output_length: fullLen }),
        ...(parsed.parsed && {
          findings: parsed.findings,
          metadata: { ...parsed.metadata, ...extraMetadata },
        }),
        ...(!parsed.parsed && Object.keys(extraMetadata).length > 0 && { metadata: extraMetadata }),
      });
    } catch (error) {
      const msg = error instanceof Error ? error.message : "Unknown error";
      if (msg.toLowerCase().includes("timeout")) {
        toolsFailed.push({ name: tool.name, command: cmd, error: "Timed out" });
      } else {
        toolsFailed.push({ name: tool.name, command: cmd, error: msg });
      }
    }
  }

  const combinedOutput = toolsRun.map(t => t.output).join("\n\n");
  const iocResult = extractIOCs(combinedOutput);

  return formatResponse("analyze_file", {
    file: args.file,
    detected_type: fileOutput,
    matched_category: category.name,
    depth,
    ...(tools.length === 0 && {
      warning: `No tools registered for category "${category.name}" at depth "${depth}". Try depth "deep" or use run_tool directly.`,
    }),
    iocs: iocResult.iocs,
    ioc_summary: iocResult.summary,
    tools_run: toolsRun,
    tools_failed: toolsFailed,
    tools_skipped: toolsSkipped,
  }, startTime);
  } catch (error) {
    return formatError("analyze_file", toREMnuxError(error), startTime);
  }
}
