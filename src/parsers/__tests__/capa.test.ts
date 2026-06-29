import { describe, it, expect } from "vitest";
import { parseCapaOutput, deriveEvidenceTypes } from "../capa.js";

// --- Synthetic capa match-node builders (shape mirrors `capa -j` output) ---
function feat(type: string, success = true, value?: string) {
  const feature: Record<string, unknown> = { type };
  if (value !== undefined) feature[type] = value;
  return { success, node: { type: "feature", feature }, children: [], locations: [] };
}
function stmt(type: string, success: boolean, children: unknown[]) {
  return { success, node: { type: "statement", statement: { type } }, children, locations: [] };
}
const ADDR = { type: "absolute", value: 0x401000 };
/** A rule with the given top-level match node(s) and optional meta. */
function rule(node: unknown, meta: Record<string, unknown> = {}) {
  return { meta, matches: [[ADDR, node]] };
}

describe("parseCapaOutput", () => {
  it("extracts rules and ATT&CK techniques", () => {
    const input = JSON.stringify({
      meta: { sample: { md5: "abc123" }, analysis: { format: "pe" } },
      rules: {
        "send HTTP request": {
          meta: {
            attack: [
              { technique: "Application Layer Protocol", id: "T1071" },
            ],
          },
        },
        "write file": {
          meta: { attack: [] },
        },
      },
    });

    const result = parseCapaOutput(input);
    expect(result.parsed).toBe(true);
    expect(result.tool).toBe("capa");
    expect(result.metadata.sample).toEqual({ md5: "abc123" });
    expect(result.metadata.analysis).toEqual({ format: "pe" });
    expect(result.findings).toHaveLength(2);

    const http = result.findings.find((f) => f.description === "send HTTP request");
    expect(http?.evidence).toBe("Application Layer Protocol (T1071)");
    expect(http?.category).toBe("capability");

    const write = result.findings.find((f) => f.description === "write file");
    expect(write?.evidence).toBeUndefined();
  });

  it("returns parsed=false on invalid JSON", () => {
    const result = parseCapaOutput("not json");
    expect(result.parsed).toBe(false);
    expect(result.findings).toHaveLength(0);
  });

  it("handles missing rules key", () => {
    const result = parseCapaOutput(JSON.stringify({ meta: {} }));
    expect(result.parsed).toBe(true);
    expect(result.findings).toHaveLength(0);
  });

  it("handles missing meta key", () => {
    const result = parseCapaOutput(JSON.stringify({ rules: {} }));
    expect(result.parsed).toBe(true);
    expect(result.metadata.sample).toBeUndefined();
  });

  it("skips malformed rule entries", () => {
    const input = JSON.stringify({
      rules: {
        "good rule": { meta: {} },
        "bad rule": null,
        "also bad": 42,
      },
    });
    const result = parseCapaOutput(input);
    expect(result.findings).toHaveLength(1);
    expect(result.findings[0].description).toBe("good rule");
  });

  it("surfaces evidence_types on findings end-to-end", () => {
    const input = JSON.stringify({
      rules: {
        "parse credit card data": rule(feat("string")),
        "create HTTP request": rule(feat("api"), { namespace: "communication/http/client" }),
      },
    });
    const result = parseCapaOutput(input);
    const artifact = result.findings.find((f) => f.description === "parse credit card data");
    const behavior = result.findings.find((f) => f.description === "create HTTP request");
    expect(artifact?.evidence_types).toEqual(["artifact"]);
    expect(behavior?.evidence_types).toEqual(["behavior"]);
  });
});

describe("deriveEvidenceTypes", () => {
  it("tags a string-only match as artifact (cardinality 1)", () => {
    expect(deriveEvidenceTypes(rule(feat("string")))).toEqual(["artifact"]);
  });

  it("tags an api match as behavior", () => {
    expect(deriveEvidenceTypes(rule(feat("api")))).toEqual(["behavior"]);
  });

  it("tags a section match as structural", () => {
    expect(deriveEvidenceTypes(rule(feat("section")))).toEqual(["structural"]);
  });

  it("tags an import match as linking", () => {
    expect(deriveEvidenceTypes(rule(feat("import")))).toEqual(["linking"]);
  });

  it("maps capa `characteristic` by value, not blanket-structural", () => {
    // code-execution characteristics → behavior (e.g. the real 'encode data using XOR')
    expect(deriveEvidenceTypes(rule(feat("characteristic", true, "nzxor")))).toEqual(["behavior"]);
    expect(deriveEvidenceTypes(rule(feat("characteristic", true, "tight loop")))).toEqual(["behavior"]);
    // file/layout characteristics → structural
    expect(deriveEvidenceTypes(rule(feat("characteristic", true, "embedded pe")))).toEqual(["structural"]);
    // string-data characteristic → artifact
    expect(deriveEvidenceTypes(rule(feat("characteristic", true, "stack string")))).toEqual(["artifact"]);
    // unknown characteristic value → no contribution (conservative)
    expect(deriveEvidenceTypes(rule(feat("characteristic", true, "some-future-char")))).toBeUndefined();
  });

  it("treats os/arch/format as neutral guards, not structural evidence", () => {
    // os:windows alone carries no evidence-kind signal
    expect(deriveEvidenceTypes(rule(feat("os", true, "windows")))).toBeUndefined();
    // os:windows + api (the real 'delay execution' shape) → behavior only, no structural noise
    const node = stmt("and", true, [feat("os", true, "windows"), feat("api")]);
    expect(deriveEvidenceTypes(rule(node))).toEqual(["behavior"]);
  });

  it("returns a multi-element set when several feature kinds matched (cardinality N)", () => {
    const node = stmt("and", true, [feat("string"), feat("api")]);
    expect(deriveEvidenceTypes(rule(node))).toEqual(["artifact", "behavior"]);
  });

  it("CRITICAL: tags from MATCHED feature nodes, not declared features", () => {
    // An `or` where the string branch matched (success) but the api branch did
    // not. Must be tagged artifact ONLY — never promoted to behavior.
    const node = stmt("or", true, [feat("string", true), feat("api", false)]);
    expect(deriveEvidenceTypes(rule(node))).toEqual(["artifact"]);
  });

  it("excludes the inner feature of a satisfied `not` (it did not match)", () => {
    const node = stmt("and", true, [feat("string", true), stmt("not", true, [feat("api", false)])]);
    expect(deriveEvidenceTypes(rule(node))).toEqual(["artifact"]);
  });

  it("adds linking from a linking/ namespace even without import features", () => {
    expect(deriveEvidenceTypes(rule(feat("api"), { namespace: "linking/runtime-linking" }))).toEqual([
      "behavior",
      "linking",
    ]);
  });

  it("does NOT infer behavior from an intent namespace like collection/*", () => {
    // namespace says "collection" but the match is a string → artifact only.
    expect(deriveEvidenceTypes(rule(feat("string"), { namespace: "collection/credit-card" }))).toEqual([
      "artifact",
    ]);
  });

  it("returns undefined when nothing can be determined (cardinality 0)", () => {
    expect(deriveEvidenceTypes({ meta: { attack: [] } })).toBeUndefined();
    expect(deriveEvidenceTypes({ meta: {}, matches: [] })).toBeUndefined();
  });

  it("is fail-soft on malformed match structures (never throws)", () => {
    expect(deriveEvidenceTypes({ matches: "not-an-array" } as unknown as Record<string, unknown>)).toBeUndefined();
    expect(deriveEvidenceTypes({ matches: [null, 42, [ADDR]] } as unknown as Record<string, unknown>)).toBeUndefined();
    expect(deriveEvidenceTypes({} as Record<string, unknown>)).toBeUndefined();
  });
});
