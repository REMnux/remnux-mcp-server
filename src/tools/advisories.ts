/**
 * Post-analysis advisory framework for cross-tool conditions.
 *
 * These advisories evaluate results across multiple tools to surface
 * actionable guidance that individual tools can't provide alone.
 */

import type { Finding } from "../parsers/types.js";

export interface PostAnalysisAdvisory {
  name: string;
  priority: number; // Higher = more important
  shouldApply: (context: AdvisoryContext) => boolean;
  issue: string;
  remediation: string;
}

export interface AdvisoryContext {
  /** `findings` are what the tool's parser resolved, when it has one. */
  toolsRun: Array<{ name: string; exit_code?: number; output?: string; findings?: Finding[] }>;
  toolsFailed?: Array<{ name: string; error?: string }>;
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
    name: "dotnet-protector",
    priority: 9,
    // Reads diec's parsed "protector: <name>" findings, whose names come from
    // DiE's signature database rather than from the sample. Plain "Confuser" is
    // the older protector, which cilantro does not list, so it does not match.
    shouldApply: (ctx) =>
      (ctx.category === "DOTNET" || ctx.category === "PE") &&
      (ctx.toolsRun.find((t) => t.name === "diec")?.findings ?? []).some(
        (f) =>
          f.category === "protector" &&
          /\.NET Reactor|ConfuserEx|\bBabel\b|Dotfuscator/i.test(f.description),
      ),
    issue:
      "diec detected a .NET protector (.NET Reactor, ConfuserEx, Babel .NET, or Dotfuscator). " +
      "Decompiled code, strings, and capa results from the protected assembly can reflect the " +
      "protection more than the program.",
    remediation:
      "Remove the protection with cilantro: run_tool command='cilantro <file> --json -o %OUTPUT%/<case>.cilantro' " +
      "with a <case> name not used before. Then decompile the cleaned assembly at the Wrote.Cleaned path, or the " +
      "embedded stages listed in the Wrote.Embedded file, with ilspycmd. To run analyze_file on a cleaned " +
      "assembly, copy it into the samples directory first.",
  },
  {
    name: "capa-file-limitation",
    priority: 9,
    // capa's limitation rules cover more than packers. analyze_file runs `capa -j`,
    // which exits 0 and lists the matched rule as a finding the parser marks
    // "limitation"; exit 14 (E_FILE_LIMITATION) appears only without -j/-v/-vv.
    shouldApply: (ctx) => {
      const capa = ctx.toolsRun.find((t) => t.name === "capa");
      return (
        capa?.exit_code === 14 ||
        (capa?.findings ?? []).some((f) => f.category === "limitation")
      );
    },
    issue:
      "capa matched one of its file-limitation rules, which it applies to packed files, installers, " +
      ".NET single-file deployments, and programs compiled from AutoIt, AutoHotkey, or Visual Basic. " +
      "capa reports the matching rule among its findings, under a name such as " +
      "\"(internal) packer file limitation\", and in a warning on stderr. For such files, capa warns that " +
      "\"the results may be misleading or incomplete\": the matched capabilities can belong to the packer, " +
      "runtime, or installer instead of the program inside.",
    remediation:
      "Unpack or extract the program and analyze that. For UPX, upx-decompress unpacks the sample in place " +
      "when it succeeds, so run analyze_file again. For AutoIt, autoit-ripper recovers the script. For an " +
      "installer, try 7z x, which opens some installer formats but not all. In the other cases, treat capa's " +
      "capabilities for this file as leads to confirm with other tools.",
  },
  {
    name: "box-js-stall",
    priority: 8,
    shouldApply: (ctx) => {
      if (ctx.category !== "JavaScript") return false;
      // t.error is server-generated ("Timed out" from analyze-file's GNU-timeout
      // detection), never sample-derived text — keep it that way if this changes.
      const timedOut = ctx.toolsFailed?.some(
        (t) => t.name === "box-js" && /\btimed\s?out\b/i.test(t.error ?? "")
      );
      // box-js's own --timeout ends the run gracefully (exit 0) and prints
      // "Analysis for <file> timed out." on stdout, so a stall can also surface
      // as a normal run. Anchor to box-js's actual banner rather than a bare
      // "timed out": a recovered string in the sample (e.g. "connection timed
      // out") must not trip the stall advisory when box-js completed cleanly.
      const reportedTimeout = ctx.toolsRun.some(
        (t) => t.name === "box-js" && t.output && /analysis for .*timed\s?out/i.test(t.output)
      );
      return Boolean(timedOut || reportedTimeout);
    },
    issue:
      "box-js stalled or timed out. On malicious JavaScript this is often anti-emulation " +
      "(e.g., a wscript self-relaunch or an environment check the sandbox cannot satisfy) — " +
      "treat the stall as a finding about the sample, not a tool failure.",
    remediation:
      "Pivot to static recovery: webcrack deobfuscates code structure and literal strings " +
      "(run_tool command='webcrack <file>'), with js-deobfuscator as a fallback. Retry box-js " +
      "with a longer --timeout only if slow unpacking, rather than anti-emulation, is suspected.",
  },
  {
    name: "box-js-self-relaunch",
    priority: 8,
    shouldApply: (ctx) => {
      if (ctx.category !== "JavaScript") return false;
      // box-js reports the sample re-invoking itself via WScript/CScript, using
      // its placeholder constant CURRENT_SCRIPT_IN_FAKED_DIR for the sample path.
      // A self-relaunch is anti-emulation: box-js runs the OUTER script (which
      // only relaunches itself) and never reaches the payload, so it exits cleanly
      // WITHOUT timing out — the box-js-stall advisory does not catch this form.
      return ctx.toolsRun.some(
        (t) =>
          t.name === "box-js" &&
          t.output &&
          /(?:wscript|cscript)(?:\.exe)?[^\n]*CURRENT_SCRIPT_IN_FAKED_DIR/i.test(t.output)
      );
    },
    issue:
      "box-js observed the script relaunching itself via WScript/CScript (a " +
      "self-referential re-invocation of the sample). This is anti-emulation: the outer " +
      "script only re-launches itself, so box-js deflects and never reaches the payload. " +
      "Values built at runtime (C2 URLs, config, decoded strings) are very likely NOT " +
      "recovered by this run or by static deobfuscation (webcrack) — even though box-js " +
      "emulated without erroring and reported no network IOCs.",
    remediation:
      "Do not read the absence of network IOCs as 'no C2'. Pivot to a method that runs the " +
      "real relaunched instance: AMSI script-block logging on a Windows host/VM (the decoded " +
      "payload surfaces in Event Viewer / Sysmon Event ID 4104), or manually resolve the " +
      "runtime string-building routine (String.fromCharCode / XOR loops) in the webcrack " +
      "output to reconstruct the assembled URL.",
  },
  {
    name: "yara-family-attribution",
    priority: 7,
    // Reads the rules yara-forge's parser resolved, so this cannot disagree with the
    // tool's summary entry or the triage token.
    shouldApply: (ctx) =>
      (ctx.toolsRun.find((t) => t.name === "yara-forge")?.findings?.length ?? 0) > 0,
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
