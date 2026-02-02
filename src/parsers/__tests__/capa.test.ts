import { describe, it, expect } from "vitest";
import { parseCapaOutput } from "../capa.js";

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
});
