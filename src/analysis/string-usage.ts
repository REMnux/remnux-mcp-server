/**
 * Pure classifier for verify_string_usage: given the strings/sections/xrefs
 * radare2 reported for a queried value, decide whether the string is referenced
 * by code — WITHOUT ever claiming it is "unused".
 *
 * The load-bearing rule (the "negative-only-when-complete" invariant): a
 * `no_code_xrefs_detected` result is emitted ONLY when analysis was provably
 * complete and well-formed. If the radare2 version/schema is unknown, the
 * binary is packed/under-analyzed, output was truncated, or a non-empty xref
 * blob failed to parse, the result is `unknown` — NEVER a negative. This mirrors
 * the check_behavior_prerequisites packed-guard: it refuses to manufacture a
 * confident "no xref" on exactly the obscured samples where static analysis is
 * unreliable.
 */

import type { R2String, R2Section, R2Xref } from "../parsers/r2.js";

export type XrefStatus =
  | "referenced_from_code"
  | "no_code_xrefs_detected"
  | "data_only"
  | "unknown";

export interface MatchGroup {
  value: string;
  /** value === query (vs a substring hit). */
  exact: boolean;
  vaddrs: Array<{ vaddr: number; section: string }>;
}

export interface MatchResult {
  value: string;
  exact: boolean;
  found_at: Array<{ vaddr: string; section: string }>;
  xref_status: XrefStatus;
  xref_count: number;
  referenced_from_initializer_only?: boolean;
  data_pointer_found?: boolean;
  xref_sources?: Array<{ from: string; fcn?: string; opcode?: string }>;
  note: string;
  recommended_followup: string;
}

export interface ClassifyContext {
  isCodeFile: boolean;
  fileType: string;
  /** `r2 -v` was parsed, so xref fields are read against a known schema. */
  schemaKnown: boolean;
  /** Analysis ran to completion, not truncated, no parse anomaly, entry resolved. */
  analysisComplete: boolean;
  /** The binary looks packed/obscured (import table / r2 coverage unreliable). */
  obscured: boolean;
  /** Addresses of functions registered as static initializers (.CRT$XCU/.init_array). */
  initializerFunctionAddrs: Set<number>;
}

const hex = (n: number): string => "0x" + (n >>> 0 === n ? n.toString(16) : n.toString(16));

/** Group string hits by distinct value (exact matches first), capped. */
export function selectMatches(
  strings: R2String[],
  query: string,
  maxMatches = 50,
): { groups: MatchGroup[]; truncated: boolean } {
  const byValue = new Map<string, MatchGroup>();
  for (const s of strings) {
    if (!s.value.includes(query)) continue;
    let g = byValue.get(s.value);
    if (!g) {
      g = { value: s.value, exact: s.value === query, vaddrs: [] };
      byValue.set(s.value, g);
    }
    g.vaddrs.push({ vaddr: s.vaddr, section: s.section });
  }
  const all = [...byValue.values()].sort((a, b) => (a.exact === b.exact ? 0 : a.exact ? -1 : 1));
  return { groups: all.slice(0, maxMatches), truncated: all.length > maxMatches };
}

/**
 * Whether a cross-reference originates from code. When section info is known,
 * the source address must fall in an executable section (this filters `aar`
 * heuristic refs whose source is in a data section). A containing function is
 * surfaced as corroborating evidence; it's used as the signal only when section
 * info is unavailable.
 */
export function isFromCode(xref: R2Xref, sections: R2Section[]): boolean {
  if (sections.length > 0) {
    return sections.some((s) => s.exec && xref.from >= s.vaddr && xref.from < s.vaddrEnd);
  }
  return xref.fcnAddr !== undefined || !!xref.fcnName;
}

const NOTE_REFERENCED =
  "At least one instruction in an executable section references this string's address. The string is reachable " +
  "from recovered code, consistent with operational use. This does not prove the referencing code executes in " +
  "any given run; confirm runtime use dynamically if the distinction matters.";

const NOTE_NO_XREFS =
  "No direct code cross-reference to this string was found by static analysis (radare2 aa; aar). This is NOT " +
  "evidence the string is unused. The reference may be computed at runtime (pointer arithmetic, indexing into a " +
  "string table, stack/heap-built copies), resolved indirectly (pointer tables, relocations, vtables/RTTI), " +
  "reachable only from code the analyzer did not recover (packed/encrypted/obfuscated regions, overlays, or " +
  "functions analysis missed), or used by a separate component. Absence of a static xref means 'no DIRECT " +
  "reference was resolvable here', not 'the string is dead or vestigial'. Do not dismiss it as a non-indicator " +
  "on this basis alone; confirm with dynamic analysis or manual review.";

const NOTE_DATA_POINTER =
  " A reference from a non-executable (data) section was found (the address is stored in a pointer/data table); " +
  "this is still not a code reference and does not by itself establish operational use.";

const NOTE_INITIALIZER =
  " The referencing function(s) are registered in the static-initializer table (.CRT$XCU/.init_array) — they run " +
  "before main as C++ static initializers. This is a structural fact about where the reference lives, with no " +
  "claim about whether the path executes in a given run.";

const NOTE_DATA_ONLY = (ft: string): string =>
  `This file is not an executable (detected type: ${ft}). It contains no code that could cross-reference the ` +
  "string, so code-xref analysis does not apply. Evaluate the string as file content on its own merits.";

const NOTE_UNKNOWN =
  "Cross-reference analysis could not be completed reliably (radare2 unavailable, analysis timed out, the binary " +
  "appears packed/obscured, output was truncated, or the version's output could not be parsed). The xref status " +
  "is UNKNOWN — this is explicitly NOT 'no xref found' and must not be read as evidence the string is unused. " +
  "Unpack first, re-run with a longer timeout (depth=deep), or analyze manually.";

const FOLLOWUP: Record<XrefStatus, string> = {
  referenced_from_code:
    "Confirm runtime use with emulation (speakeasy) or sandbox detonation; a static reference does not guarantee the path runs.",
  no_code_xrefs_detected:
    "If this string matters to your assessment, confirm via dynamic analysis or manual review — do NOT record it as unused.",
  data_only: "Use the analysis tools appropriate for this file type.",
  unknown: "Unpack the sample, increase the timeout (depth=deep), or analyze manually, then re-check.",
};

/**
 * Classify one matched string value against the xrefs r2 reported for its
 * address(es). `xrefs` is the parsed union across the group's vaddrs;
 * `rawXrefParseAnomaly` is true when r2 emitted a non-empty xref blob that did
 * not parse (version field drift — must degrade to `unknown`, never a negative).
 */
export function classifyMatch(
  group: MatchGroup,
  xrefs: R2Xref[],
  sections: R2Section[],
  ctx: ClassifyContext,
  rawXrefParseAnomaly = false,
): MatchResult {
  const found_at = group.vaddrs.map((v) => ({ vaddr: hex(v.vaddr), section: v.section }));
  const base = { value: group.value, exact: group.exact, found_at };

  if (!ctx.isCodeFile) {
    return {
      ...base,
      xref_status: "data_only",
      xref_count: 0,
      note: NOTE_DATA_ONLY(ctx.fileType || "unknown"),
      recommended_followup: FOLLOWUP.data_only,
    };
  }

  const codeXrefs = xrefs.filter((x) => isFromCode(x, sections));

  if (codeXrefs.length > 0) {
    const initOnly =
      ctx.initializerFunctionAddrs.size > 0 &&
      codeXrefs.every((x) => x.fcnAddr !== undefined && ctx.initializerFunctionAddrs.has(x.fcnAddr));
    const xref_sources = codeXrefs.slice(0, 10).map((x) => ({
      from: hex(x.from),
      ...(x.fcnName ? { fcn: x.fcnName } : {}),
      ...(x.opcode ? { opcode: x.opcode } : {}),
    }));
    return {
      ...base,
      xref_status: "referenced_from_code",
      xref_count: codeXrefs.length,
      ...(initOnly ? { referenced_from_initializer_only: true } : {}),
      xref_sources,
      note: NOTE_REFERENCED + (initOnly ? NOTE_INITIALIZER : ""),
      recommended_followup: FOLLOWUP.referenced_from_code,
    };
  }

  // No code xref. A negative is allowed ONLY when analysis was provably complete.
  const degraded = !ctx.schemaKnown || !ctx.analysisComplete || ctx.obscured || rawXrefParseAnomaly;
  if (degraded) {
    return {
      ...base,
      xref_status: "unknown",
      xref_count: 0,
      note: NOTE_UNKNOWN,
      recommended_followup: FOLLOWUP.unknown,
    };
  }

  const dataPointerFound = xrefs.length > 0; // refs exist, but none from code
  return {
    ...base,
    xref_status: "no_code_xrefs_detected",
    xref_count: 0,
    ...(dataPointerFound ? { data_pointer_found: true } : {}),
    note: NOTE_NO_XREFS + (dataPointerFound ? NOTE_DATA_POINTER : ""),
    recommended_followup: FOLLOWUP.no_code_xrefs_detected,
  };
}
