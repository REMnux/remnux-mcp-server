import { describe, it, expect } from "vitest";
import { parseToolOutput, hasParser } from "../index.js";

describe("parseToolOutput", () => {
  it("routes diec to its parser", () => {
    const input = JSON.stringify({ detects: [{ values: [{ type: "Packer", name: "UPX" }] }] });
    const result = parseToolOutput("diec", input);
    expect(result.parsed).toBe(true);
    expect(result.tool).toBe("diec");
  });

  it("routes unknown tools to passthrough", () => {
    const result = parseToolOutput("strings", "some output");
    expect(result.parsed).toBe(false);
    expect(result.tool).toBe("strings");
  });
});

describe("hasParser", () => {
  it("returns true for registered parsers", () => {
    expect(hasParser("diec")).toBe(true);
    expect(hasParser("pdfid")).toBe(true);
    expect(hasParser("capa")).toBe(true);
  });

  it("returns false for unregistered tools", () => {
    expect(hasParser("strings")).toBe(false);
    expect(hasParser("exiftool")).toBe(false);
  });
});
