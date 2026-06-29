/**
 * Pre-claim triage discipline checklist — server-authored, bundled, offline.
 *
 * This is operational guidance on USING the analysis tools and reasoning about
 * evidence (the gates to pass before asserting a behavioral claim). It is
 * deliberately distinct from the report-WRITING guidelines in
 * content.generated.ts, which are synced from zeltser.com; this content is the
 * same category as the server's other locally-authored guidance (the
 * analyze_file analysis_guidance, the advisories, the suggest_tools hints) and
 * is therefore authored and versioned here.
 *
 * Upgrade path: if this should later be published and reused on zeltser.com, it
 * can graduate to the synced report-guidance pipeline without changing the
 * `triage_checklist` topic's interface. Until then it is bundled and offline —
 * no live network fetch (the server's works-offline guarantee is load-bearing
 * for air-gapped REMnux deployments).
 */
export const TRIAGE_DISCIPLINE = {
  version: "1.0.0",
  title: "Malware triage discipline — gates to pass before making a claim",
  provenance: "Server-authored operational guidance, bundled and offline (not synced from zeltser.com).",
  core_principle:
    "Separate ARTIFACT-level evidence (a string, regex, constant, or capa pattern is PRESENT in the file) from " +
    "BEHAVIORAL evidence (reachable code actually performs the action). The presence of an artifact is not proof " +
    "the behavior executes. Most over-confident triage errors come from restating an artifact as a behavior.",
  before_claiming_a_behavior: [
    "Are the required APIs imported, or resolvable at runtime (GetProcAddress + LoadLibrary*)? If neither, the behavior is not statically supported.",
    "If the required APIs are absent but the binary is packed / encrypted / high-entropy, the honest answer is 'indeterminate — unpack first', not 'incapable'. Static absence on an obscured binary proves nothing.",
    "Are the relevant data artifacts (strings, wallet addresses, regexes) cross-referenced from executable code? Data sitting in .rdata with no code xref is an artifact, not an operational indicator.",
    "Is the relevant code reachable from the entry point, or only from unused / initializer-only code?",
    "Did dynamic analysis (emulation, sandbox) actually exercise the suspected path? Static analysis alone cannot confirm a runtime behavior.",
    "Distinguish 'the code to do X is present' (a capability) from 'the sample does X' (a confirmed behavior). Until confirmed, write 'capable of' or 'consistent with', not 'performs'.",
  ],
  for_each_ioc: [
    "Operationally used (referenced by reachable code, or observed in traffic) vs. vestigial (present in the file but unreferenced)?",
    "Pyramid-of-Pain tier — trivially changed by the adversary (hash, IP) or costly (tooling, TTP)?",
    "Pivotable to other samples / campaigns, or unique to this sample?",
  ],
  for_confidence: [
    "Direct evidence vs. inferential leap — how many assumptions sit between the observation and the claim?",
    "Single-source vs. corroborated across independent tools or methods.",
    "Use ICD-203 estimative language; state attribution confidence separately from detection confidence.",
  ],
  using_this_server: [
    "capa findings carry evidence_types (artifact / behavior / structural / linking), and analyze_file returns a capability_evidence field separating behavior_capable from artifact_only — read those before asserting a behavior.",
    "A YARA family match is resemblance, not identity. A family name in the filename is a lead to test, never a finding.",
    "When you need behavioral confirmation, plan for emulation (speakeasy) or sandbox detonation rather than inferring it from static artifacts.",
  ],
} as const;
