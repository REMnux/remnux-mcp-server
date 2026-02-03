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
import { filterStderrNoise } from "../utils/stderr-filter.js";
import { getPreprocessors } from "../tools/preprocessors.js";

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

const DEFAULT_OUTPUT_BUDGET = 40 * 1024; // 40KB default
const TOTAL_RESPONSE_BUDGET = 120 * 1024; // 120KB total across all tools

/** Per-tool output budgets — tools known to produce large output get tighter limits. */
const TOOL_OUTPUT_BUDGETS: Record<string, number> = {
  capa: 30 * 1024,
  "capa-vv": 30 * 1024,
  floss: 20 * 1024,
  ilspycmd: 15 * 1024,
  pcodedmp: 15 * 1024,
  strings: 15 * 1024,
  rtfdump: 10 * 1024,
  olevba: 30 * 1024,
  oledump: 20 * 1024,
  exiftool: 10 * 1024,
  zipdump: 15 * 1024,
  base64dump: 15 * 1024,
  "js-beautify": 15 * 1024,
  "box-js": 20 * 1024,
  cfr: 15 * 1024,
  jadx: 15 * 1024,
  manalyze: 15 * 1024,
  "tshark-verbose": 30 * 1024,
  "tshark-dns": 15 * 1024,
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

  const filePath = (config.mode === "local" && args.file.startsWith("/")) ? args.file : `${config.samplesDir}/${args.file}`;
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

  // Compute the file's own hashes so we can filter them from IOC results
  const ownHashes = new Set<string>();
  try {
    const hashResult = await connector.execute(
      ["sh", "-c", `md5sum '${filePath.replace(/'/g, "'\\''")}' && sha1sum '${filePath.replace(/'/g, "'\\''")}' && sha256sum '${filePath.replace(/'/g, "'\\''")}'`],
      { timeout: 30000 },
    );
    if (hashResult.exitCode === 0) {
      for (const line of hashResult.stdout.split("\n")) {
        const hash = line.trim().split(/\s+/)[0];
        if (hash && /^[a-fA-F0-9]{32,128}$/.test(hash)) {
          ownHashes.add(hash.toLowerCase());
        }
      }
    }
  } catch { /* best effort — if hashing fails, we just skip filtering */ }

  // Step 2: Match to category and get tools from registry by tag + depth
  const category = matchFileType(fileOutput, args.file);
  const tag = CATEGORY_TAG_MAP[category.name] ?? "fallback";
  const tools = toolRegistry.byTagAndTier(tag, depth);

  // Step 2b: Run applicable preprocessors
  let analysisPath = filePath;
  const preprocessResults: Array<{ name: string; description: string; outputPath?: string; error?: string }> = [];

  for (const pp of getPreprocessors(category.name)) {
    try {
      const detect = await connector.executeShell(pp.detectCommand(filePath), {
        timeout: 10000,
        cwd: config.samplesDir,
      });
      if (detect.exitCode !== 0) continue; // Not applicable

      const safeFile = args.file.replace(/[^a-zA-Z0-9._-]/g, "_");
      const outPath = `${config.outputDir}/preprocessed-${pp.name}-${safeFile}`;
      const result = await connector.executeShell(pp.processCommand(filePath, outPath), {
        timeout: pp.timeout,
        cwd: config.samplesDir,
      });

      if (result.exitCode === 0) {
        analysisPath = outPath;
        preprocessResults.push({ name: pp.name, description: pp.description, outputPath: outPath });
      } else {
        preprocessResults.push({
          name: pp.name,
          description: pp.description,
          error: result.stderr?.trim() || `Exit code ${result.exitCode}`,
        });
      }
    } catch (error) {
      preprocessResults.push({
        name: pp.name,
        description: pp.description,
        error: error instanceof Error ? error.message : "Unknown error",
      });
    }
  }

  const toolsRun: ToolRun[] = [];
  const toolsFailed: ToolFailed[] = [];
  const toolsSkipped: ToolSkipped[] = [];
  let totalOutputSize = 0;

  // Step 3: Run each tool
  for (const tool of tools) {
    const cmd = buildCommandFromDefinition(tool, analysisPath, config.outputDir);

    // Ensure output directories exist for tools that write to --output-dir
    if (tool.fixedArgs && config.outputDir) {
      const dirIdx = tool.fixedArgs.indexOf("--output-dir");
      if (dirIdx !== -1 && tool.fixedArgs[dirIdx + 1]) {
        const rawDir = tool.fixedArgs[dirIdx + 1];
        const resolvedDir = rawDir.startsWith("/tmp/")
          ? rawDir.replace("/tmp/", config.outputDir + "/")
          : rawDir;
        try {
          await connector.execute(["mkdir", "-p", resolvedDir], { timeout: 5000 });
        } catch { /* best effort */ }
      }
    }

    // Use the greater of user-specified timeout and tool's own timeout
    const effectiveTimeout = Math.max(perToolTimeout, (tool.timeout ?? 60) * 1000);

    try {
      const result = await connector.executeShell(cmd, {
        timeout: effectiveTimeout,
        cwd: config.samplesDir,
      });

      let stderr = result.stderr || "";
      stderr = filterStderrNoise(stderr);
      // Detect missing tools — only match shell "command not found" or exit code 127,
      // not tool output that happens to contain "not found" (e.g., pescan "section not found")
      const isNotInstalled = result.exitCode === 127 ||
        /command not found/i.test(stderr) ||
        (result.exitCode !== 0 && /^.*: No such file or directory$/m.test(stderr) && stderr.includes(tool.command));
      if (isNotInstalled) {
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

      // Check for tool-specific exit code hints
      const extraMetadata: Record<string, unknown> = {};
      const hint = tool.exitCodeHints?.[result.exitCode];
      if (hint) {
        extraMetadata.analyst_note = hint;
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

  const combinedOutput = toolsRun.map(t => t.output).join("\n\n")
    .replace(/^\s*"command":\s*".*"$/gm, "");
  const iocResult = extractIOCs(combinedOutput);

  // Filter out the analyzed file's own hashes from IOC results
  if (ownHashes.size > 0) {
    iocResult.iocs = iocResult.iocs.filter((ioc) => !ownHashes.has(ioc.value.toLowerCase()));
  }

  return formatResponse("analyze_file", {
    file: args.file,
    detected_type: fileOutput,
    matched_category: category.name,
    depth,
    ...(preprocessResults.length > 0 && { preprocessing: preprocessResults }),
    analysis_guidance:
      "IMPORTANT: Many capabilities flagged by analysis tools (API imports like GetProcAddress/VirtualProtect, " +
      "memory operations, TLS sections, anti-debug patterns) are common in BOTH malware and legitimate software. " +
      "Do not assume malicious intent from flagged items alone. For each finding, consider: " +
      "(1) Is this expected for legitimate software of this type? " +
      "(2) Do multiple findings together suggest malicious purpose, or are they individually " +
      "explainable as normal development practices? " +
      "(3) What concrete evidence distinguishes this from a benign program? " +
      "State your confidence level (low/medium/high) and what evidence supports or contradicts a malicious verdict.",
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
    return formatError("analyze_file", toREMnuxError(error, deps.config.mode), startTime);
  }
}
