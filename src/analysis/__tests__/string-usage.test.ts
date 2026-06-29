import { describe, it, expect } from "vitest";
import { selectMatches, isFromCode, classifyMatch, type ClassifyContext, type MatchGroup } from "../string-usage.js";
import type { R2String, R2Section, R2Xref } from "../../parsers/r2.js";

const SECTIONS: R2Section[] = [
  { name: ".text", vaddr: 0x1000, vaddrEnd: 0x2000, exec: true },
  { name: ".rdata", vaddr: 0x2000, vaddrEnd: 0x3000, exec: false },
];
const codeXref: R2Xref = { from: 0x1100, type: "STRN", fcnAddr: 0x10a0, fcnName: "main", opcode: "lea rax, str.x" };
const dataXref: R2Xref = { from: 0x2100, type: "DATA" };

const group: MatchGroup = { value: "secret", exact: true, vaddrs: [{ vaddr: 0x2048, section: ".rdata" }] };
function ctx(over: Partial<ClassifyContext> = {}): ClassifyContext {
  return { isCodeFile: true, fileType: "PE32", schemaKnown: true, analysisComplete: true, obscured: false, ...over };
}

describe("selectMatches", () => {
  it("groups by distinct value, exact matches first, with a cap", () => {
    const strings: R2String[] = [
      { value: "abc", vaddr: 1, section: ".rdata" },
      { value: "abcdef", vaddr: 2, section: ".rdata" },
      { value: "abc", vaddr: 3, section: ".data" },
    ];
    const { groups, truncated } = selectMatches(strings, "abc");
    expect(groups[0].value).toBe("abc"); // exact first
    expect(groups[0].exact).toBe(true);
    expect(groups[0].vaddrs).toHaveLength(2); // deduped by value
    expect(truncated).toBe(false);
  });

  it("caps and flags truncation", () => {
    const strings: R2String[] = Array.from({ length: 5 }, (_, i) => ({ value: `q${i}`, vaddr: i, section: "" }));
    const { groups, truncated } = selectMatches(strings, "q", 3);
    expect(groups).toHaveLength(3);
    expect(truncated).toBe(true);
  });
});

describe("isFromCode", () => {
  it("true when the source is in an executable section", () => {
    expect(isFromCode(codeXref, SECTIONS)).toBe(true);
  });
  it("false when the source is only in a data section (filters aar heuristic refs)", () => {
    expect(isFromCode(dataXref, SECTIONS)).toBe(false);
  });
  it("falls back to containing-function attribution when section info is absent", () => {
    expect(isFromCode({ from: 0x1100, type: "STRN", fcnName: "main" }, [])).toBe(true);
    expect(isFromCode({ from: 0x1100, type: "DATA" }, [])).toBe(false);
  });
});

describe("classifyMatch", () => {
  it("referenced_from_code when a code xref exists", () => {
    const r = classifyMatch(group, [codeXref], SECTIONS, ctx());
    expect(r.xref_status).toBe("referenced_from_code");
    expect(r.xref_count).toBe(1);
    expect(r.xref_sources?.[0]).toMatchObject({ fcn: "main" });
  });

  it("no_code_xrefs_detected only when analysis is complete — and the note refuses to say 'unused'", () => {
    const r = classifyMatch(group, [], SECTIONS, ctx());
    expect(r.xref_status).toBe("no_code_xrefs_detected");
    expect(r.note).toContain("This is NOT evidence the string is unused");
  });

  it("data_only for a non-code file", () => {
    const r = classifyMatch(group, [], [], ctx({ isCodeFile: false }));
    expect(r.xref_status).toBe("data_only");
  });

  // --- THE INVARIANT: a negative is NEVER emitted when analysis is degraded ---
  it("packed/obscured + no xref → unknown (NOT a false negative)", () => {
    const r = classifyMatch(group, [], SECTIONS, ctx({ obscured: true }));
    expect(r.xref_status).toBe("unknown");
    expect(r.recommended_followup).toMatch(/unpack/i);
  });

  it("unknown when the r2 version/schema was not captured", () => {
    expect(classifyMatch(group, [], SECTIONS, ctx({ schemaKnown: false })).xref_status).toBe("unknown");
  });

  it("unknown when analysis did not complete", () => {
    expect(classifyMatch(group, [], SECTIONS, ctx({ analysisComplete: false })).xref_status).toBe("unknown");
  });

  it("unknown on a raw-xref parse anomaly (version field drift)", () => {
    // axtj returned content but it did not parse → must degrade, never a negative.
    const r = classifyMatch(group, [], SECTIONS, ctx(), true);
    expect(r.xref_status).toBe("unknown");
  });

  it("GUARD: no degraded context ever yields no_code_xrefs_detected", () => {
    for (const over of [{ obscured: true }, { schemaKnown: false }, { analysisComplete: false }]) {
      expect(classifyMatch(group, [], SECTIONS, ctx(over)).xref_status).not.toBe("no_code_xrefs_detected");
    }
    expect(classifyMatch(group, [], SECTIONS, ctx(), true).xref_status).not.toBe("no_code_xrefs_detected");
  });

  it("data_pointer_found when only a data-section reference exists", () => {
    const r = classifyMatch(group, [dataXref], SECTIONS, ctx());
    expect(r.xref_status).toBe("no_code_xrefs_detected");
    expect(r.data_pointer_found).toBe(true);
    expect(r.note).toMatch(/non-executable \(data\) section/i);
  });
});
