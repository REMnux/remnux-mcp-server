/**
 * Common types for structured tool output parsing.
 */

/** A single finding extracted from tool output. */
export interface Finding {
  /** What was found (e.g., "UPX packer detected", "VBA macro present") */
  description: string;
  /** Severity: info, low, medium, high, critical */
  severity?: "info" | "low" | "medium" | "high" | "critical";
  /** Optional category (e.g., "packer", "capability", "indicator") */
  category?: string;
  /** Raw evidence from tool output */
  evidence?: string;
}

/** Structured metadata extracted from tool output. */
export interface ParsedToolOutput {
  /** Tool that produced this output */
  tool: string;
  /** Whether parsing succeeded (false = fell back to passthrough) */
  parsed: boolean;
  /** Structured findings, if any */
  findings: Finding[];
  /** Key-value metadata extracted from output */
  metadata: Record<string, unknown>;
  /** Raw output preserved for reference */
  raw: string;
}

/** A parser function: takes raw output, returns structured data. */
export type ToolOutputParser = (rawOutput: string) => ParsedToolOutput;
