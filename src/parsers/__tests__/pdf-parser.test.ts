import { describe, it, expect } from "vitest";
import { parsePdfParserOutput } from "../pdf-parser.js";

const SAMPLE_OUTPUT = `Comment: 5
XREF: 1
Trailer: 1
StartXref: 1
Indirect object: 49
Indirect object with stream: 3
  49 0 R:
Search keywords:
 /JS 1: 7
 /JavaScript 1: 7
 /OpenAction 1: 1
 /URI 13: 10, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28
 /Annot 13: 10, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28
 /Page 2: 3, 4`;

describe("parsePdfParserOutput", () => {
  it("extracts keyword counts and object lists", () => {
    const result = parsePdfParserOutput(SAMPLE_OUTPUT);
    expect(result.parsed).toBe(true);
    expect(result.tool).toBe("pdf-parser");

    const kw = result.metadata.keywords as Record<string, { count: number; objects: number[] }>;
    expect(kw["/URI"].count).toBe(13);
    expect(kw["/URI"].objects).toEqual([10, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28]);
    expect(kw["/JS"].count).toBe(1);
    expect(kw["/JS"].objects).toEqual([7]);
    expect(kw["/Page"].count).toBe(2);
    expect(kw["/Page"].objects).toEqual([3, 4]);
  });

  it("flags suspicious keywords with correct severity", () => {
    const result = parsePdfParserOutput(SAMPLE_OUTPUT);
    const descriptions = result.findings.map((f) => f.description);
    expect(descriptions).toContain("Notable keyword /JS found (count: 1)");
    expect(descriptions).toContain("Notable keyword /JavaScript found (count: 1)");
    expect(descriptions).toContain("Notable keyword /OpenAction found (count: 1)");
    expect(descriptions).toContain("Notable keyword /URI found (count: 13)");

    const js = result.findings.find((f) => f.description.includes("/JS found"));
    expect(js?.severity).toBe("high");
    const uri = result.findings.find((f) => f.description.includes("/URI"));
    expect(uri?.severity).toBe("medium");
  });

  it("does not flag benign keywords", () => {
    const result = parsePdfParserOutput(SAMPLE_OUTPUT);
    const descriptions = result.findings.map((f) => f.description);
    expect(descriptions).not.toContain(expect.stringContaining("/Page"));
    expect(descriptions).not.toContain(expect.stringContaining("/Annot"));
  });

  it("parses structural summary lines", () => {
    const result = parsePdfParserOutput(SAMPLE_OUTPUT);
    const structure = result.metadata.structure as Record<string, number>;
    expect(structure["Comment"]).toBe(5);
    expect(structure["Indirect object"]).toBe(49);
    expect(structure["XREF"]).toBe(1);
    expect(structure["Trailer"]).toBe(1);
  });

  it("does not flag zero-count keywords", () => {
    const output = " /JS 0: 0";
    const result = parsePdfParserOutput(output);
    // Keyword is parsed but no finding generated
    const kw = result.metadata.keywords as Record<string, { count: number; objects: number[] }>;
    expect(kw["/JS"].count).toBe(0);
    expect(result.findings).toHaveLength(0);
  });

  it("returns parsed=false for empty input", () => {
    const result = parsePdfParserOutput("");
    expect(result.parsed).toBe(false);
    expect(result.findings).toHaveLength(0);
  });

  it("returns parsed=false for unrelated output", () => {
    const result = parsePdfParserOutput("totally unrelated output\nnothing here");
    expect(result.parsed).toBe(false);
    expect(result.findings).toHaveLength(0);
  });
});
