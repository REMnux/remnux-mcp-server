/**
 * Smart output summarization for analyze_file responses.
 *
 * When total output exceeds the budget, generates a summary with key findings
 * per tool while preserving IOCs and providing paths to full outputs.
 */

import type { Finding } from "../parsers/types.js";

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

interface IOC {
  type: string;
  value: string;
  context?: string;
  confidence?: number;
}

interface IOCSummary {
  total: number;
  noise_filtered: number;
  by_type: Record<string, number>;
  truncated?: string[];
}

interface ToolFailed {
  name: string;
  command: string;
  error: string;
}

interface ToolSkipped {
  name: string;
  command: string;
  reason: string;
  skip_type: "not_installed" | "not_applicable" | "requires_user_args";
}

interface PreprocessResult {
  name: string;
  description: string;
  outputPath?: string;
  error?: string;
}

export interface ToolSummary {
  name: string;
  status: "findings" | "clean" | "error" | "timeout";
  key_lines: string[];
  finding_count?: number;
  output_size: number;
  saved_to?: string;
}

export interface AnalysisSummary {
  [key: string]: unknown;
  mode: "summary";
  file: string;
  detected_type: string;
  matched_category: string;
  depth: string;
  triage_summary: string;
  preprocessing?: PreprocessResult[];
  total_tools: number;
  tools_with_findings: number;
  tools: ToolSummary[];
  tools_failed: ToolFailed[];
  tools_skipped: ToolSkipped[];
  iocs: IOC[];
  ioc_summary: IOCSummary;
  suggested_next_steps: string[];
  full_output_hint: string;
  analysis_guidance: string;
  workflow_hint?: string;
}

/** Threshold in bytes above which we switch to summary mode */
const SUMMARY_THRESHOLD_BYTES = 32000;

/** Maximum key lines to extract per tool */
const MAX_KEY_LINES_PER_TOOL = 5;

/**
 * Determine if the combined tool output warrants summarization.
 */
export function shouldSummarize(toolsRun: ToolRun[]): boolean {
  const total = toolsRun.reduce((sum, t) => sum + (t.output?.length || 0), 0);
  return total > SUMMARY_THRESHOLD_BYTES;
}

/**
 * Extract the most informative lines from tool output.
 *
 * Prioritizes lines with:
 * - Findings/detections (contains "found", "detected", "match", "suspicious")
 * - Errors/warnings
 * - URLs, IPs, hashes
 * - Capability names and indicators
 *
 * Avoids:
 * - Banner/header lines (version info, separators)
 * - Empty lines
 * - Repetitive lines
 */
export function extractKeyLines(output: string, limit: number = MAX_KEY_LINES_PER_TOOL): string[] {
  if (!output || output.length === 0) return [];

  const lines = output.split("\n");
  const scored: Array<{ line: string; score: number }> = [];
  const seen = new Set<string>();

  // Patterns that indicate informative content (weighted)
  // NOTE: Using generic heuristics only, not malware-specific patterns
  const highValuePatterns = [
    /found|detected|match|suspicious|capability|indicator/i,
    /\b(?:https?:\/\/|ftp:\/\/)[^\s]+/i,
    /\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b/,
    /\b[a-fA-F0-9]{32}\b|\b[a-fA-F0-9]{40}\b|\b[a-fA-F0-9]{64}\b/,
    /error|warning|fail|exception/i,
    /MITRE|ATT&CK|T\d{4}/i,
    /risk|threat|anomaly|unusual|notable/i,
  ];

  // Patterns that indicate noise (to deprioritize)
  const noisePatterns = [
    /^[-=_*]{3,}$/,
    /^version|^copyright|^license|^\s*$/i,
    /^usage:|^options:/i,
    /^\s*\d+\s*$/,
    /^#|^\/\//,
  ];

  for (const rawLine of lines) {
    const line = rawLine.trim();
    if (!line || line.length < 5 || line.length > 500) continue;

    // Skip duplicates
    const normalized = line.toLowerCase().replace(/\s+/g, " ");
    if (seen.has(normalized)) continue;
    seen.add(normalized);

    // Calculate score
    let score = 0;

    // High-value patterns add points
    for (const pattern of highValuePatterns) {
      if (pattern.test(line)) score += 10;
    }

    // Noise patterns subtract points
    for (const pattern of noisePatterns) {
      if (pattern.test(line)) score -= 20;
    }

    // Lines with structured data (key: value) are often informative
    if (/^[A-Za-z_][A-Za-z0-9_]*\s*[:=]\s*.+/.test(line)) score += 3;

    // Lines mentioning specific counts or results
    if (/\b\d+\s+(match|found|detect|hit|result)/i.test(line)) score += 5;

    if (score > 0) {
      scored.push({ line, score });
    }
  }

  // Sort by score descending, take top N
  scored.sort((a, b) => b.score - a.score);
  return scored.slice(0, limit).map((s) => s.line);
}

/**
 * Determine the status of a tool run.
 */
function getToolStatus(tool: ToolRun): "findings" | "clean" | "error" | "timeout" {
  if (tool.exit_code !== 0) {
    if (tool.output?.toLowerCase().includes("timeout")) return "timeout";
    // Some tools exit non-zero but still produce findings
    if (tool.findings && tool.findings.length > 0) return "findings";
    return "error";
  }
  if (tool.findings && tool.findings.length > 0) return "findings";
  return "clean";
}

/**
 * Generate a summarized analysis response.
 */
export function generateSummary(
  file: string,
  detectedType: string,
  category: string,
  depth: string,
  triageSummary: string,
  toolsRun: ToolRun[],
  toolsFailed: ToolFailed[],
  toolsSkipped: ToolSkipped[],
  preprocessResults: PreprocessResult[],
  iocs: IOC[],
  iocSummary: IOCSummary,
  nextSteps: string[],
  analysisGuidance: string,
  workflowHint?: string,
): AnalysisSummary {
  const toolSummaries: ToolSummary[] = [];
  const savedFiles: string[] = [];

  for (const tool of toolsRun) {
    const status = getToolStatus(tool);
    const keyLines = extractKeyLines(tool.output);

    // Track which files were saved for full output retrieval
    const savedMatch = tool.output?.match(/Full output: output\/([^\s\]]+)/);
    const savedTo = savedMatch ? savedMatch[1] : undefined;
    if (savedTo) savedFiles.push(savedTo);

    toolSummaries.push({
      name: tool.name,
      status,
      key_lines: keyLines,
      ...(tool.findings && tool.findings.length > 0 && { finding_count: tool.findings.length }),
      output_size: tool.output?.length || 0,
      ...(savedTo && { saved_to: savedTo }),
    });
  }

  const toolsWithFindings = toolSummaries.filter((t) => t.status === "findings").length;

  return {
    mode: "summary",
    file,
    detected_type: detectedType,
    matched_category: category,
    depth,
    triage_summary: triageSummary,
    ...(preprocessResults.length > 0 && { preprocessing: preprocessResults }),
    total_tools: toolsRun.length,
    tools_with_findings: toolsWithFindings,
    tools: toolSummaries,
    tools_failed: toolsFailed,
    tools_skipped: toolsSkipped,
    iocs,
    ioc_summary: iocSummary,
    suggested_next_steps: nextSteps,
    full_output_hint:
      savedFiles.length > 0
        ? `Full tool outputs saved to output directory. Use download_file to retrieve: ${savedFiles.join(", ")}`
        : "Use run_tool to re-run specific tools for full output.",
    analysis_guidance: analysisGuidance,
    ...(workflowHint && { workflow_hint: workflowHint }),
  };
}
