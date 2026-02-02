import { describe, it, expect } from "vitest";
import { parseOlevbaOutput } from "../olevba.js";

describe("parseOlevbaOutput", () => {
  it("detects VBA macros from VBA MACRO lines", () => {
    const output = [
      "olevba 0.60.1 on Python 3",
      "VBA MACRO ThisDocument.cls",
      "VBA MACRO Module1.bas",
    ].join("\n");

    const result = parseOlevbaOutput(output);
    expect(result.parsed).toBe(true);
    expect(result.metadata.has_macros).toBe(true);
    expect(result.metadata.macro_count).toBe(2);
  });

  it("extracts suspicious keywords from summary table", () => {
    const output = [
      "| Suspicious | Shell            | May run an executable |",
      "| Suspicious | CreateObject     | May create an OLE object |",
    ].join("\n");

    const result = parseOlevbaOutput(output);
    expect(result.parsed).toBe(true);
    expect(result.metadata.notable_keywords).toContain("Shell");
    expect(result.metadata.notable_keywords).toContain("CreateObject");
  });

  it("extracts AutoExec triggers", () => {
    const output = "| AutoExec | AutoOpen | Runs when document is opened |";
    const result = parseOlevbaOutput(output);
    expect(result.findings).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ category: "auto-execute", severity: "high" }),
      ])
    );
  });

  it("extracts IOC rows", () => {
    const output = "| IOC | http://evil.com/payload | URL found in macro |";
    const result = parseOlevbaOutput(output);
    expect(result.findings).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ category: "ioc", severity: "high" }),
      ])
    );
  });

  it("detects suspicious patterns in raw output", () => {
    const output = "Dim obj As Object\nSet obj = CreateObject(\"WScript.Shell\")\nobj.Run \"PowerShell -enc ...\"";
    const result = parseOlevbaOutput(output);
    expect(result.parsed).toBe(true);
    const categories = result.findings.map((f) => f.category);
    expect(categories).toContain("execution");
  });

  it("returns unparsed for empty output", () => {
    const result = parseOlevbaOutput("");
    expect(result.parsed).toBe(false);
    expect(result.findings).toHaveLength(0);
  });
});
