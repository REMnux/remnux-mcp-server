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
  /**
   * For capability findings (e.g. capa): the kind(s) of evidence the match
   * actually relied on, derived from the feature nodes that matched. An
   * unordered, deduplicated set describing HOW the rule matched — not a verdict
   * on what the sample does. Absent when it cannot be determined (treat absence
   * as "unknown", not "none").
   *   - artifact   — matched on strings/regex/bytes (data present, not necessarily executed)
   *   - behavior   — matched on API calls, mnemonics, or other code semantics
   *   - structural — matched on sections, file characteristics, format/arch
   *   - linking    — matched on imports / runtime-linking
   */
  evidence_types?: EvidenceType[];
}

/**
 * The kind of evidence a capability match relied on (see Finding.evidence_types).
 * A `string` artifact match proves the data is present; it does NOT prove the
 * binary executes the corresponding behavior. Only a `behavior` match (API
 * calls, mnemonics) is code-level evidence.
 */
export type EvidenceType = "artifact" | "behavior" | "structural" | "linking";

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
