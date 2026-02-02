import { describe, it, expect } from "vitest";
import { parseDiecOutput } from "../diec.js";

describe("parseDiecOutput", () => {
  it("parses detections from diec JSON", () => {
    const input = JSON.stringify({
      filetype: "PE32",
      detects: [
        {
          values: [
            { type: "Packer", name: "UPX", version: "3.96" },
            { type: "Compiler", name: "MSVC" },
          ],
        },
      ],
    });

    const result = parseDiecOutput(input);
    expect(result.parsed).toBe(true);
    expect(result.tool).toBe("diec");
    expect(result.metadata.filetype).toBe("PE32");
    expect(result.findings).toHaveLength(2);
    expect(result.findings[0]).toEqual({
      description: "Packer: UPX",
      category: "packer",
      severity: "info",
      evidence: "version: 3.96",
    });
    expect(result.findings[1]).toEqual({
      description: "Compiler: MSVC",
      category: "compiler",
      severity: "info",
    });
  });

  it("handles top-level array format", () => {
    const input = JSON.stringify([
      { values: [{ type: "Linker", name: "GNU ld" }] },
    ]);

    const result = parseDiecOutput(input);
    expect(result.parsed).toBe(true);
    expect(result.findings).toHaveLength(1);
    expect(result.findings[0].description).toBe("Linker: GNU ld");
  });

  it("returns parsed=false on invalid JSON", () => {
    const result = parseDiecOutput("not json at all");
    expect(result.parsed).toBe(false);
    expect(result.findings).toHaveLength(0);
    expect(result.raw).toBe("not json at all");
  });

  it("handles empty detects array", () => {
    const result = parseDiecOutput(JSON.stringify({ detects: [] }));
    expect(result.parsed).toBe(true);
    expect(result.findings).toHaveLength(0);
  });

  it("skips malformed values entries", () => {
    const input = JSON.stringify({
      detects: [{ values: [null, 42, { type: "Packer", name: "UPX" }] }],
    });
    const result = parseDiecOutput(input);
    expect(result.findings).toHaveLength(1);
  });

  it("defaults type/name when missing", () => {
    const input = JSON.stringify({ detects: [{ values: [{}] }] });
    const result = parseDiecOutput(input);
    expect(result.findings[0].description).toBe("detection: unknown");
  });
});
