import { describe, it, expect } from "vitest";
import { passthroughParser } from "../passthrough.js";

describe("passthroughParser", () => {
  it("returns parsed=false with empty findings", () => {
    const result = passthroughParser("strings", "some raw output");
    expect(result).toEqual({
      tool: "strings",
      parsed: false,
      findings: [],
      metadata: {},
      raw: "some raw output",
    });
  });

  it("preserves tool name", () => {
    expect(passthroughParser("exiftool", "").tool).toBe("exiftool");
  });

  it("handles empty output", () => {
    const result = passthroughParser("tool", "");
    expect(result.parsed).toBe(false);
    expect(result.raw).toBe("");
  });
});
