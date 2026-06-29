/**
 * Parser for CAPA JSON output.
 *
 * Extracts capabilities and their associated ATT&CK techniques.
 * Expects JSON output from `capa -j <file>`.
 */

import type { ParsedToolOutput, Finding, EvidenceType } from "./types.js";

/**
 * Map a capa feature-node type to the kind of evidence it represents.
 *
 * Deliberately conservative: only feature types whose evidence kind is
 * unambiguous are mapped. A rule's namespace describes its INTENT
 * (e.g. "collection/*"), not how it matched, so it is NOT used here to infer
 * behavior — conflating the two is exactly the artifact-vs-behavior error this
 * tagging exists to prevent.
 */
const FEATURE_EVIDENCE_TYPE: Record<string, EvidenceType> = {
  // artifact — data/content patterns present in the binary
  string: "artifact",
  substring: "artifact",
  regex: "artifact",
  bytes: "artifact",
  // behavior — code-level semantics (these feature types occur only in code)
  api: "behavior",
  mnemonic: "behavior",
  number: "behavior",
  offset: "behavior",
  "operand number": "behavior",
  "operand offset": "behavior",
  // structural — binary layout / metadata
  section: "structural",
  export: "structural",
  // linking — imports / library presence
  import: "linking",
  // Intentionally NEUTRAL (no contribution): os, arch, format, match, class,
  // property, namespace, function-name. These are environment guards or
  // ambiguous signals that would dilute the artifact-vs-behavior distinction
  // (e.g. `os: windows` appears in many behavioral rules as a guard).
};

/**
 * capa's `characteristic` feature is overloaded: some values describe binary
 * structure, others describe code execution. Map by value; unknown values
 * contribute nothing (conservative — a mislabel is worse than no label).
 */
const CHARACTERISTIC_EVIDENCE_TYPE: Record<string, EvidenceType> = {
  // structural — file/layout characteristics
  "embedded pe": "structural",
  "mixed mode": "structural",
  "forwarded export": "structural",
  // artifact — string data (constructed in code, but still data)
  "stack string": "artifact",
  // behavior — code-execution characteristics
  loop: "behavior",
  "tight loop": "behavior",
  "recursive call": "behavior",
  nzxor: "behavior",
  "peb access": "behavior",
  "fs access": "behavior",
  "gs access": "behavior",
  "cross section flow": "behavior",
  "indirect call": "behavior",
  "unmanaged call": "behavior",
};

/** Stable ordering for the unordered evidence_types set (deterministic output). */
const EVIDENCE_TYPE_ORDER: EvidenceType[] = ["artifact", "behavior", "structural", "linking"];

/**
 * Walk a capa match-node tree and collect the feature types of nodes that
 * ACTUALLY matched (success === true). capa includes non-matching branches
 * (the untaken side of an `or`, the inner feature of a satisfied `not`) with
 * success === false; excluding them ensures a rule that fired on a `string`
 * branch is never credited with an unmatched `api` branch.
 */
function collectMatchedEvidenceTypes(node: unknown, out: Set<EvidenceType>): void {
  if (!node || typeof node !== "object") return;
  const n = node as Record<string, unknown>;
  const inner = n.node;
  if (n.success === true && inner && typeof inner === "object") {
    const i = inner as Record<string, unknown>;
    if (i.type === "feature" && i.feature && typeof i.feature === "object") {
      const f = i.feature as Record<string, unknown>;
      const ft = f.type;
      if (typeof ft === "string") {
        if (ft === "characteristic") {
          const val = typeof f.characteristic === "string" ? f.characteristic : "";
          const et = CHARACTERISTIC_EVIDENCE_TYPE[val];
          if (et) out.add(et);
        } else {
          const et = FEATURE_EVIDENCE_TYPE[ft];
          if (et) out.add(et);
        }
      }
    }
  }
  if (Array.isArray(n.children)) {
    for (const c of n.children) collectMatchedEvidenceTypes(c, out);
  }
}

/**
 * Derive the evidence_types set for a single capa rule from the feature nodes
 * that actually matched, plus two unambiguous namespace signals. Returns
 * undefined when nothing can be determined (the caller then omits the field).
 * Never throws — a malformed rule yields undefined, never a lost finding.
 */
export function deriveEvidenceTypes(rule: Record<string, unknown>): EvidenceType[] | undefined {
  try {
    const types = new Set<EvidenceType>();

    if (Array.isArray(rule.matches)) {
      for (const m of rule.matches) {
        // each match is [address, matchNode]
        if (Array.isArray(m) && m.length >= 2) {
          collectMatchedEvidenceTypes(m[1], types);
        }
      }
    }

    // Namespace carries an unambiguous evidence-kind signal in two cases only.
    const meta = rule.meta;
    if (meta && typeof meta === "object" && !Array.isArray(meta)) {
      const ns = (meta as Record<string, unknown>).namespace;
      if (typeof ns === "string") {
        if (ns.startsWith("linking/")) types.add("linking");
        else if (ns.startsWith("executable/")) types.add("structural");
      }
    }

    if (types.size === 0) return undefined;
    return EVIDENCE_TYPE_ORDER.filter((t) => types.has(t));
  } catch {
    return undefined;
  }
}

export function parseCapaOutput(rawOutput: string): ParsedToolOutput {
  const result: ParsedToolOutput = {
    tool: "capa",
    parsed: false,
    findings: [],
    metadata: {},
    raw: rawOutput,
  };

  try {
    const data = JSON.parse(rawOutput);
    result.parsed = true;

    // Extract rules/capabilities
    const rules = data.rules;
    if (rules && typeof rules === "object" && !Array.isArray(rules)) {
      for (const [name, rule] of Object.entries(rules)) {
        if (!rule || typeof rule !== "object") continue;
        const r = rule as Record<string, unknown>;
        const meta = r.meta;
        const finding: Finding = {
          description: name,
          category: "capability",
          severity: "info",
        };

        // Extract ATT&CK info if present — validate array structure
        if (meta && typeof meta === "object" && !Array.isArray(meta)) {
          const m = meta as Record<string, unknown>;
          if (Array.isArray(m.attack) && m.attack.length > 0) {
            finding.evidence = m.attack
              .filter((a): a is Record<string, string> => a && typeof a === "object")
              .map((a) => `${a.technique ?? "?"} (${a.id ?? "?"})`)
              .join(", ");
          }
        }

        // Tag the kind(s) of evidence the rule actually matched on (artifact vs
        // behavior vs structural vs linking). Additive and fail-soft: if this
        // cannot be determined the field is simply omitted — the finding's name
        // and ATT&CK evidence are never affected.
        const evidenceTypes = deriveEvidenceTypes(r);
        if (evidenceTypes) finding.evidence_types = evidenceTypes;

        result.findings.push(finding);
      }
    }

    // Extract metadata
    if (data.meta && typeof data.meta === "object") {
      result.metadata.sample = data.meta.sample;
      result.metadata.analysis = data.meta.analysis;
    }

    // Provide helpful context when no capabilities are found
    if (result.findings.length === 0) {
      result.metadata.no_findings_reason =
        "No capabilities identified. This may occur when: " +
        "(1) the file is packed/obfuscated and capa cannot analyze the unpacked code, " +
        "(2) the file is a stub/loader with minimal functionality, " +
        "(3) the file's behaviors don't match capa's rule set, or " +
        "(4) the file format isn't fully supported. " +
        "Consider: running a packer detector first (diec, yara), " +
        "unpacking the sample, or using complementary tools like strings/floss.";
    }
  } catch {
    // JSON parse failed — return unparsed
  }

  return result;
}
