/**
 * Optional-section convention — server-authored, bundled, offline.
 *
 * The bundled report template (content.generated.ts, synced from zeltser.com)
 * marks three sections as optional by suffixing "(Optional)" to the heading —
 * e.g. "## Detection Engineering (Optional)". That suffix is a CONDITIONAL
 * MARKER for the drafter, the same category as the template's square-bracketed
 * "[...remove before finalizing]" guidance. Without an instruction saying so,
 * an AI copies the marker straight into the finished heading. This constant is
 * that instruction.
 *
 * Like TRIAGE_DISCIPLINE, this is server-authored operational guidance on USING
 * the bundled content, deliberately distinct from the report-WRITING guidelines
 * synced from zeltser.com. It is authored and versioned here, bundled and
 * offline (no live network fetch — the works-offline guarantee is load-bearing
 * for air-gapped REMnux deployments).
 *
 * NOTE: `applies_to[].identifier` intentionally carries the "(Optional)"-suffixed
 * names, because the synced guidelines digest (situationalSections,
 * longReportSections, reviewCriteriaSectionMap) uses those suffixed names as the
 * section IDENTIFIERS. A drift-guard test derives the "(Optional)" headings from
 * REPORT_TEMPLATE and asserts they match this list, so a future rename upstream
 * fails a test rather than silently going stale.
 */
export const OPTIONAL_SECTION_CONVENTION = {
  version: "1.0.0",
  title: "Optional-section convention — how to handle template headings marked (Optional)",
  provenance:
    "Server-authored guidance on using the bundled template, bundled and offline (not synced from zeltser.com).",
  principle:
    "A section heading (and its Contents entry) whose text ends in \"(Optional)\" is a CONDITIONAL MARKER, " +
    "not literal heading text. Exactly like the square-bracketed guidance the template tells you to remove " +
    "before finalizing, the \"(Optional)\" suffix is an instruction to act on, not something to copy into the " +
    "finished report. A finished report must never contain the word \"(Optional)\" in a heading.",
  applies_to: [
    {
      identifier: "Infection Vector (Optional)",
      finished_heading: "## Infection Vector",
      anchor: "#infection-vector",
      trigger: "The delivery path is known and the report should document how the sample reached the target.",
    },
    {
      identifier: "Detection Engineering (Optional)",
      finished_heading: "## Detection Engineering",
      anchor: "#detection-engineering",
      trigger: "You are publishing detection logic or hunting guidance alongside the analysis.",
    },
    {
      identifier: "Appendix: Analysis Scripts (Optional)",
      finished_heading: "## Appendix: Analysis Scripts",
      anchor: "#appendix-analysis-scripts",
      trigger: "You are sharing config extractors, deobfuscation or unpacking scripts, or analysis notebooks.",
    },
  ],
  how_to_apply: [
    "Include an optional section only when the analysis produced findings relevant to it, or the user " +
      "explicitly asked for it. Each section's trigger above mirrors the guidelines' situationalSections " +
      "(get_report_guidance topic=\"profiles\").",
    "When you include one, strip \"(Optional)\" from the heading, its Contents entry, AND every in-document link " +
      "that targets the section — the Contents anchor and any cross-reference, such as the Sample Snapshot " +
      "\"Infection Vector\" row. For example: \"## Detection Engineering (Optional)\" becomes \"## Detection " +
      "Engineering\"; the Contents line \"[Detection Engineering (Optional)](#detection-engineering-optional)\" " +
      "becomes \"[Detection Engineering](#detection-engineering)\"; and the Sample Snapshot link " +
      "\"[Infection Vector](#infection-vector-optional)\" becomes \"[Infection Vector](#infection-vector)\".",
    "When you omit one, also remove its Contents entry AND any cross-reference to it — for example the " +
      "\"Infection Vector\" row in the Sample Snapshot table, whose link is " +
      "\"[Infection Vector](#infection-vector-optional)\".",
    "Do NOT rewrite the \"(Optional)\"-suffixed names where they appear as IDENTIFIERS in the guidelines " +
      "digest (situationalSections, longReportSections, reviewCriteriaSectionMap). Those are stable " +
      "identifiers; the suffix is stripped only in the finished report's heading, Contents entry, and anchor.",
  ],
} as const;
