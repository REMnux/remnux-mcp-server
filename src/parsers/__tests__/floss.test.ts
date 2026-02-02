import { describe, it, expect } from "vitest";
import { parseFlossOutput } from "../floss.js";

describe("parseFlossOutput", () => {
  it("parses decoded strings section", () => {
    const output = `
─── FLOSS DECODED STRINGS ───
http://evil.com/c2
secret_key_123
`;
    const result = parseFlossOutput(output);
    expect(result.parsed).toBe(true);
    const decoded = result.findings.find((f) => f.category === "floss-decoded");
    expect(decoded).toBeDefined();
    expect(decoded!.description).toContain("2 decoded strings");
    expect(decoded!.severity).toBe("medium");
  });

  it("parses all four sections", () => {
    const output = `
─── FLOSS STATIC STRINGS ───
hello
world
─── FLOSS DECODED STRINGS ───
decoded1
─── FLOSS STACK STRINGS ───
stack1
stack2
─── FLOSS TIGHT STRINGS ───
tight1
`;
    const result = parseFlossOutput(output);
    expect(result.parsed).toBe(true);
    expect(result.metadata.string_counts).toEqual({
      static: 2,
      decoded: 1,
      stack: 2,
      tight: 1,
    });
    expect(result.findings).toHaveLength(4);
  });

  it("omits static strings when packed", () => {
    const output = `
─── FLOSS STATIC STRINGS ───
garbage1
garbage2
─── FLOSS DECODED STRINGS ───
real_string
`;
    const result = parseFlossOutput(output, { packed: true });
    expect(result.parsed).toBe(true);
    const staticFinding = result.findings.find((f) => f.category === "floss-static");
    expect(staticFinding).toBeUndefined();
    expect(result.metadata.static_strings_omitted).toBe(true);
  });

  it("caps static strings at 100", () => {
    const statics = Array.from({ length: 150 }, (_, i) => `string_${i}`);
    const output = `─── FLOSS STATIC STRINGS ───\n${statics.join("\n")}`;
    const result = parseFlossOutput(output);
    expect(result.parsed).toBe(true);
    const staticFinding = result.findings.find((f) => f.category === "floss-static");
    expect(staticFinding!.description).toContain("showing first 100");
    expect(staticFinding!.evidence!.split("\n")).toHaveLength(100);
  });

  it("returns unparsed when no strings found", () => {
    const result = parseFlossOutput("FLOSS version 2.3\nNo strings found.");
    expect(result.parsed).toBe(false);
    expect(result.findings).toHaveLength(0);
  });
});
