import { describe, it, expect } from "vitest";
import { parsePdfidOutput } from "../pdfid.js";

const SAMPLE_OUTPUT = `PDFiD 0.2.8 sample.pdf
 PDF Header: %PDF-1.4
 obj                   12
 endobj                12
 stream                 3
 endstream              3
 xref                   1
 trailer                1
 startxref              1
 /Page                  2
 /Encrypt               0
 /ObjStm                0
 /JS                    1
 /JavaScript            1
 /AA                    0
 /OpenAction            1
 /AcroForm              0
 /JBIG2Decode           0
 /RichMedia             0
 /Launch                0
 /EmbeddedFile          0
 /XFA                   0
 /URI                   0`;

describe("parsePdfidOutput", () => {
  it("extracts keyword counts", () => {
    const result = parsePdfidOutput(SAMPLE_OUTPUT);
    expect(result.parsed).toBe(true);
    expect(result.tool).toBe("pdfid");

    const kw = result.metadata.keywords as Record<string, number>;
    expect(kw["/Page"]).toBe(2);
    expect(kw["/JS"]).toBe(1);
    expect(kw["/Encrypt"]).toBe(0);
  });

  it("flags suspicious keywords with count > 0", () => {
    const result = parsePdfidOutput(SAMPLE_OUTPUT);
    const descriptions = result.findings.map((f) => f.description);
    expect(descriptions).toContain("Notable keyword /JS found (count: 1)");
    expect(descriptions).toContain("Notable keyword /JavaScript found (count: 1)");
    expect(descriptions).toContain("Notable keyword /OpenAction found (count: 1)");
  });

  it("assigns high severity to /JS and /JavaScript", () => {
    const result = parsePdfidOutput(SAMPLE_OUTPUT);
    const js = result.findings.find((f) => f.description.includes("/JS found"));
    const openAction = result.findings.find((f) => f.description.includes("/OpenAction"));
    expect(js?.severity).toBe("high");
    expect(openAction?.severity).toBe("medium");
  });

  it("does not flag keywords with count 0", () => {
    const result = parsePdfidOutput(SAMPLE_OUTPUT);
    const descriptions = result.findings.map((f) => f.description);
    expect(descriptions).not.toContain(expect.stringContaining("/AA"));
    expect(descriptions).not.toContain(expect.stringContaining("/Launch"));
  });

  it("returns parsed=false for non-pdfid output", () => {
    const result = parsePdfidOutput("totally unrelated output\nno keywords here");
    expect(result.parsed).toBe(false);
    expect(result.findings).toHaveLength(0);
  });

  it("handles empty input", () => {
    const result = parsePdfidOutput("");
    expect(result.parsed).toBe(false);
  });
});
