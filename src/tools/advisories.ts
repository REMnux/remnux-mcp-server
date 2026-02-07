/**
 * Post-analysis advisory framework for cross-tool conditions.
 *
 * These advisories evaluate results across multiple tools to surface
 * actionable guidance that individual tools can't provide alone.
 */

export interface PostAnalysisAdvisory {
  name: string;
  priority: number; // Higher = more important
  shouldApply: (context: AdvisoryContext) => boolean;
  issue: string;
  remediation: string;
}

export interface AdvisoryContext {
  toolsRun: Array<{ name: string; exit_code?: number; output?: string }>;
  category: string;
}

export const POST_ANALYSIS_ADVISORIES: PostAnalysisAdvisory[] = [
  {
    name: "autoit-wrapper",
    priority: 10,
    shouldApply: (ctx) => {
      const ripperFailed = ctx.toolsRun.some(
        (t) => t.name === "autoit-ripper" && t.exit_code !== 0
      );
      const diecAutoIt = ctx.toolsRun.some(
        (t) => t.name === "diec" && t.output && /AutoIt|AU3!/i.test(t.output)
      );
      return ripperFailed && diecAutoIt;
    },
    issue:
      "autoit-ripper failed but diec detected AutoIt. Script is nested inside IExpress/CAB/SFX wrapper.",
    remediation:
      "Extract inner files: run_tool command='7z x \"<file>\" -oextracted/' then analyze extracted .exe files",
  },
  {
    name: "capa-packed",
    priority: 9,
    shouldApply: (ctx) => {
      const capa = ctx.toolsRun.find((t) => t.name === "capa");
      return capa?.exit_code === 14; // Packed file exit code
    },
    issue: "File is packed. Capa analysis is limited.",
    remediation:
      "Unpack with upx -d (if UPX) or specialized unpacker, then re-analyze for better coverage.",
  },
  {
    name: "yara-family-attribution",
    priority: 7,
    shouldApply: (ctx) => {
      const forge = ctx.toolsRun.find((t) => t.name === "yara-forge");
      if (!forge?.output) return false;
      const lines = forge.output.trim().split("\n");
      return lines.some((line) => {
        const trimmed = line.trim();
        return trimmed.length > 0 &&
               !trimmed.startsWith("warning:") &&
               !trimmed.startsWith("error:");
      });
    },
    issue:
      "YARA family signatures matched. These indicate resemblance to known malware families " +
      "based on static patterns, not confirmed attribution. Signatures can match shared code, " +
      "common libraries, or reused techniques across unrelated families.",
    remediation:
      "Cross-reference with behavioral analysis, network IOCs, or threat intel (e.g., VirusTotal) " +
      "before attributing to a specific family. Use 'matches signatures associated with [family]' " +
      "rather than 'identified as [family]'.",
  },
];

/**
 * Evaluate all advisories against the analysis context.
 * Returns matching advisories sorted by priority (highest first).
 */
export function evaluateAdvisories(
  context: AdvisoryContext
): PostAnalysisAdvisory[] {
  return POST_ANALYSIS_ADVISORIES.filter((a) => a.shouldApply(context)).sort(
    (a, b) => b.priority - a.priority
  );
}
