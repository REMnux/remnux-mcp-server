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
import { shouldSummarize, generateSummary } from "../analysis/index.js";

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
interface ToolSkipped {
  name: string;
  command: string;
  reason: string;
  /** Categorizes why the tool was skipped for clearer UX */
  skip_type: "not_installed" | "not_applicable" | "requires_user_args";
}

/** Generate suggested next steps based on file category and analysis results */
function generateNextSteps(
  category: string,
  depth: DepthTier,
  toolsRun: ToolRun[],
  toolsSkipped: ToolSkipped[],
  iocCount: number
): string[] {
  const steps: string[] = [];

  // Depth-based suggestions
  if (depth === "quick") {
    steps.push("Run with depth='standard' for more thorough analysis (capa, YARA rules, etc.)");
  } else if (depth === "standard") {
    steps.push("Run with depth='deep' for exhaustive analysis including floss string deobfuscation, decompilation, and XOR brute-force");
  }

  // Category-specific suggestions
  switch (category) {
    case "PE":
    case "DOTNET":
      if (!toolsRun.some(t => t.name === "capa" && t.findings && t.findings.length > 0)) {
        steps.push("File may be packed — try unpacking with 'upx -d' or specialized unpackers before re-analysis");
      }
      steps.push("For dynamic analysis: use run_tool with 'speakeasy -t <file>' to emulate execution");
      steps.push("Search for strings in specific sections: run_tool command='strings -a -n 8 <file>'");
      break;
    case "PDF":
      steps.push("Extract suspicious objects: run_tool command='pdf-parser.py -o <obj_num> -d <file>'");
      steps.push("Decode JavaScript streams: run_tool command='pdf-parser.py -o <obj_num> -f -d <file>'");
      break;
    case "OLE2":
    case "OOXML":
      steps.push("Extract specific macro streams: run_tool command='oledump.py -s <stream_num> -v <file>'");
      steps.push("Decode VBA p-code for stomped macros: run_tool command='pcodedmp <file>'");
      break;
    case "Shellcode":
      steps.push("Emulate 32-bit shellcode: run_tool command='speakeasy -t <file> -r -a x86'");
      steps.push("Emulate 64-bit shellcode: run_tool command='speakeasy -t <file> -r -a amd64'");
      break;
    case "DataWithPEExtension":
      steps.push("Emulate as shellcode: run_tool command='speakeasy -t <file> -r -a x86' (try amd64 if no output)");
      steps.push("Check for Cobalt Strike beacon: run_tool command='1768.py <file>'");
      steps.push("Extract encoded content: run_tool command='base64dump.py -n 20 <file>'");
      break;
    case "PCAP":
      steps.push("Extract HTTP objects: run_tool command='tshark -r <file> --export-objects http,/tmp/http-objects'");
      steps.push("Follow TCP stream: run_tool command='tshark -r <file> -z follow,tcp,ascii,0'");
      break;
    case "Memory":
      steps.push("Dump suspicious process: run_tool command='vol3 -f <file> windows.memmap --pid <pid> --dump'");
      steps.push("Extract injected code: run_tool command='vol3 -f <file> windows.malfind --dump'");
      break;
  }

  // IOC-based suggestions
  if (iocCount > 0) {
    steps.push("Extracted IOCs are in the 'iocs' field — consider threat intel lookup for network indicators");
  }

  // Tool-not-installed suggestions
  const notInstalled = toolsSkipped.filter(t => t.skip_type === "not_installed");
  if (notInstalled.length > 0) {
    steps.push(`${notInstalled.length} tool(s) not installed — run check_tools to see installation status`);
  }

  return steps.slice(0, 5); // Limit to 5 most relevant suggestions
}

/** Generate a brief triage summary from analysis results */
function generateTriageSummary(
  category: string,
  toolsRun: ToolRun[],
  iocCount: number
): string {
  const findings: string[] = [];

  // Count findings by severity
  let highCount = 0;
  let mediumCount = 0;
  for (const tool of toolsRun) {
    if (tool.findings) {
      for (const f of tool.findings) {
        if (f.severity === "high") highCount++;
        else if (f.severity === "medium") mediumCount++;
      }
    }
  }

  // Check for specific indicators
  const hasCapabilities = toolsRun.some(t =>
    t.name === "capa" && t.findings && t.findings.length > 0
  );
  const hasMacros = toolsRun.some(t =>
    t.name === "olevba" && t.output && !t.output.includes("No VBA macros found")
  );
  const hasPackerDetection = toolsRun.some(t =>
    t.name === "diec" && t.output && /packer|protector|crypter/i.test(t.output)
  );
  const hasAnomaly = toolsRun.some(t =>
    (t.name === "portex" || t.name === "pescan") && t.findings && t.findings.length > 0
  );
  const hasYaraMatches = toolsRun.some(t =>
    t.name === "yara-rules" && t.output && t.output.trim().length > 0 && !t.output.includes("No matches")
  );
  const hasFamilyDetection = toolsRun.some(t => {
    if (t.name !== "yara-forge" || !t.output) return false;
    // Check for actual YARA matches: lines that aren't warnings/errors
    const lines = t.output.trim().split("\n");
    return lines.some(line => {
      const trimmed = line.trim();
      return trimmed.length > 0 &&
             !trimmed.startsWith("warning:") &&
             !trimmed.startsWith("error:");
    });
  });

  // Detect shellcode loader/stub pattern: no imports + W+X section + low entropy
  const hasNoImports = toolsRun.some(t =>
    t.name === "yara-rules" && t.output?.includes("ImportTableIsBad")
  );
  const hasWriteExecute = toolsRun.some(t =>
    (t.name === "portex" || t.name === "pescan") &&
    t.output && /write.*execute|self-modifying/i.test(t.output)
  );
  const hasLowEntropy = toolsRun.some(t =>
    t.name === "portex" && t.output && /entropy[:\s]+0\.\d+/i.test(t.output)
  );
  const isShellcodeLoaderPattern = hasNoImports && hasWriteExecute && hasLowEntropy;

  // Build summary
  findings.push(`File type: ${category}`);

  // Surface key container/packer detections from ALL tool outputs
  const allOutput = toolsRun.map(t => t.output || "").join(" ");

  if (/IExpress|WEXTRACT|Cabinet Self-Extractor/i.test(allOutput)) {
    findings.push("IExpress SFX");
  }
  if (/NSIS|Nullsoft/i.test(allOutput)) {
    findings.push("NSIS installer");
  }
  if (/Inno\s*Setup/i.test(allOutput)) {
    findings.push("Inno Setup");
  }
  if (/PyInstaller/i.test(allOutput)) {
    findings.push("PyInstaller");
  }
  if (/AutoIt|AU3!/i.test(allOutput)) {
    findings.push("AutoIt compiled");
  }
  if (/Themida|VMProtect|Enigma/i.test(allOutput)) {
    findings.push("protected");
  }
  if (/\bUPX\b/i.test(allOutput)) {
    findings.push("UPX packed");
  }

  if (isShellcodeLoaderPattern) findings.push("⚠️ Shellcode loader pattern (no imports + W+X section + low entropy)");
  if (hasPackerDetection) findings.push("Packer/protector detected");
  if (hasAnomaly) findings.push("PE anomalies detected");
  if (hasCapabilities) findings.push("Notable capabilities identified");
  if (hasMacros) findings.push("VBA macros present");
  if (hasFamilyDetection) findings.push("Malware family identified");
  if (hasYaraMatches) findings.push("YARA rules matched");

  if (highCount > 0) findings.push(`${highCount} high-severity finding(s)`);
  else if (mediumCount > 0) findings.push(`${mediumCount} medium-severity finding(s)`);

  if (iocCount > 0) findings.push(`${iocCount} IOC(s) extracted`);

  const toolsSucceeded = toolsRun.length;
  findings.push(`${toolsSucceeded} tool(s) completed`);

  return findings.join(" | ");
}

const DEFAULT_OUTPUT_BUDGET = 40 * 1024; // 40KB default
const TOTAL_RESPONSE_BUDGET = 120 * 1024; // 120KB total across all tools
const MAX_SAVED_OUTPUT_SIZE = 500 * 1024; // 500KB max saved file

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

/** Parsing hints for querying large output files with jq/grep */
const PARSING_HINTS: Record<string, string[]> = {
  capa: [
    "Count capabilities: run_tool command='jq \".rules | keys | length\" output/<file>'",
    "List ATT&CK techniques: run_tool command='jq -r \".rules[].attack[].technique\" output/<file> | sort -u'",
    "Show specific capability: run_tool command='jq \".rules[\\\"<capability-name>\\\"]\" output/<file>'",
  ],
  floss: [
    "Search for URLs: run_tool command='grep -oE \"https?://[^\\\"]+\" output/<file> | sort -u'",
    "Search for IPs: run_tool command='grep -oE \"[0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+\" output/<file> | sort -u'",
    "Find base64 strings: run_tool command='grep -E \"^[A-Za-z0-9+/]{20,}=*$\" output/<file>'",
  ],
  olevba: [
    "Show VBA code only: run_tool command='grep -A 100 \"VBA MACRO\" output/<file>'",
    "Find suspicious keywords: run_tool command='grep -iE \"shell|exec|powershell|cmd\" output/<file>'",
  ],
  strings: [
    "Search for URLs: run_tool command='grep -oE \"https?://[^\\\"]+\" output/<file> | sort -u'",
    "Search for paths: run_tool command='grep -E \"[A-Za-z]:\\\\\\\\|/usr/|/etc/\" output/<file>'",
  ],
};

export async function handleAnalyzeFile(
  deps: HandlerDeps,
  args: AnalyzeFileArgs
) {
  const startTime = Date.now();
  try {
  const { connector, config } = deps;
  const depth = (args.depth ?? "standard") as DepthTier;

  // Workflow hint for non-default depth
  const workflowHint = depth === "deep"
    ? "TIP: For most files, depth='standard' (the default, ~30-90s) provides sufficient coverage. Use 'deep' only when standard analysis doesn't reveal enough, or for exhaustive investigation."
    : undefined;

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
    // Skip tools that require user-supplied arguments (can't auto-run)
    if (tool.requiresUserArgs) {
      toolsSkipped.push({
        name: tool.name,
        command: tool.command,
        reason: "Requires user-supplied arguments (use run_tool manually)",
        skip_type: "requires_user_args",
      });
      continue;
    }

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

      // Detect Python TypeError/AttributeError indicating wrong file type for tool
      // Only trigger when stderr contains Python traceback AND output is minimal
      const isPythonTypeError = result.exitCode !== 0 &&
        /^Traceback \(most recent call last\):/m.test(stderr) &&
        /TypeError|AttributeError|ValueError|KeyError|IndexError|ImportError|ModuleNotFoundError|FileNotFoundError|UnicodeDecodeError/i.test(stderr) &&
        !/command not found/i.test(stderr);

      if (isPythonTypeError) {
        const hint = tool.exitCodeHints?.[result.exitCode] ||
          `Tool encountered error on this file type (${stderr.match(/(?:TypeError|AttributeError|ValueError|KeyError|IndexError|ImportError|ModuleNotFoundError|FileNotFoundError|UnicodeDecodeError)[^\n]*/)?.[0] || "see stderr"})`;
        toolsSkipped.push({
          name: tool.name,
          command: cmd,
          reason: hint,
          skip_type: "not_applicable",
        });
        continue;
      }

      // Detect missing tools — only match shell "command not found" or exit code 127,
      // not tool output that happens to contain "not found" (e.g., pescan "section not found")
      const isNotInstalled = result.exitCode === 127 ||
        /command not found/i.test(stderr) ||
        (result.exitCode !== 0 && /^.*: No such file or directory$/m.test(stderr) && stderr.includes(tool.command));
      if (isNotInstalled) {
        toolsSkipped.push({
          name: tool.name,
          command: cmd,
          reason: "Tool not installed",
          skip_type: "not_installed",
        });
        continue;
      }

      // Detect timeout via GNU timeout exit codes (124 = SIGTERM timeout, 137 = SIGKILL)
      const isTimeout = result.exitCode === 124 || result.exitCode === 137;
      if (isTimeout) {
        toolsFailed.push({ name: tool.name, command: cmd, error: "Timed out" });
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
        // Save full output to output dir for later retrieval (if under size limit)
        const safeFile = args.file.replace(/[^a-zA-Z0-9._-]/g, "_");
        const outFilename = `${tool.name}-${safeFile}.txt`;

        if (fullLen <= MAX_SAVED_OUTPUT_SIZE) {
          try {
            const outPath = `${config.outputDir}/${outFilename}`;
            await connector.writeFile(outPath, Buffer.from(output, "utf-8"));
            savedOutputFile = outFilename;
          } catch {
            // Non-fatal: truncation hint won't include file reference
          }
        }

        // Build truncation message with optional parsing hints
        const hints = PARSING_HINTS[tool.name]?.map(h => h.replace(/<file>/g, outFilename));
        let truncationMsg: string;
        if (savedOutputFile) {
          truncationMsg = `\n\n[Truncated at ${Math.round(budget / 1024)}KB of ${Math.round(fullLen / 1024)}KB total. Full output: output/${savedOutputFile}]`;
          if (hints && hints.length > 0) {
            truncationMsg += `\n[Query with: ${hints[0]}]`;
          }
        } else if (fullLen > MAX_SAVED_OUTPUT_SIZE) {
          truncationMsg = `\n\n[Output too large (${Math.round(fullLen / 1024)}KB) to save. Re-run tool with filters.]`;
        } else {
          truncationMsg = `\n\n[Truncated at ${Math.round(budget / 1024)}KB of ${Math.round(fullLen / 1024)}KB total]`;
        }

        output = output.slice(0, budget) + truncationMsg;
      }

      totalOutputSize += output.length;

      const parsed = parseToolOutput(tool.name, output);

      // Check for tool-specific exit code hints
      const extraMetadata: Record<string, unknown> = {};
      const hint = tool.exitCodeHints?.[result.exitCode];
      if (hint) {
        extraMetadata.analyst_note = hint;
      }

      // Extract capa summary from JSON output for compact overview
      if (tool.name === "capa" && tool.outputFormat === "json" && result.stdout) {
        try {
          const capaData = JSON.parse(result.stdout);
          if (capaData.rules) {
            const rules = capaData.rules as Record<string, { attack?: Array<{ technique: string }> }>;
            const attackTechniques = [...new Set(
              Object.values(rules)
                .flatMap((r) => r.attack || [])
                .map((a) => a.technique)
            )];
            extraMetadata.capa_summary = {
              capability_count: Object.keys(rules).length,
              attack_techniques: attackTechniques,
              top_capabilities: Object.keys(rules).slice(0, 10),
            };
          }
        } catch {
          // JSON parse failed, skip summary extraction
        }
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

  // Generate triage summary and next steps
  const triageSummary = generateTriageSummary(category.name, toolsRun, iocResult.iocs.length);
  const suggestedNextSteps = generateNextSteps(
    category.name,
    depth,
    toolsRun,
    toolsSkipped,
    iocResult.iocs.length
  );

  const analysisGuidance =
    "IMPORTANT: Many capabilities flagged by analysis tools (API imports like GetProcAddress/VirtualProtect, " +
    "memory operations, TLS sections, anti-debug patterns) are common in BOTH malware and legitimate software. " +
    "Do not assume malicious intent from flagged items alone. For each finding, consider: " +
    "(1) Is this expected for legitimate software of this type? " +
    "(2) Do multiple findings together suggest malicious purpose, or are they individually " +
    "explainable as normal development practices? " +
    "(3) What concrete evidence distinguishes this from a benign program? " +
    "State your confidence level (low/medium/high) and what evidence supports or contradicts a malicious verdict.";

  // Check if output exceeds budget - return summary instead of full output
  if (shouldSummarize(toolsRun)) {
    const summary = generateSummary(
      args.file,
      fileOutput,
      category.name,
      depth,
      triageSummary,
      toolsRun,
      toolsFailed,
      toolsSkipped,
      preprocessResults,
      iocResult.iocs,
      iocResult.summary,
      suggestedNextSteps,
      analysisGuidance,
      workflowHint,
    );
    return formatResponse("analyze_file", summary, startTime);
  }

  return formatResponse("analyze_file", {
    file: args.file,
    detected_type: fileOutput,
    matched_category: category.name,
    depth,
    triage_summary: triageSummary,
    ...(preprocessResults.length > 0 && { preprocessing: preprocessResults }),
    analysis_guidance: analysisGuidance,
    ...(workflowHint && { workflow_hint: workflowHint }),
    ...(tools.length === 0 && {
      warning: `No tools registered for category "${category.name}" at depth "${depth}". Try depth "deep" or use run_tool directly.`,
    }),
    suggested_next_steps: suggestedNextSteps,
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
