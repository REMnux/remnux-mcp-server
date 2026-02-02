import { describe, it, expect } from "vitest";
import { parseOleidOutput } from "../oleid.js";

describe("parseOleidOutput", () => {
  it("parses table format with risk indicators", () => {
    const output = [
      "| Indicator       | Value | Risk    |",
      "| --------------- | ----- | ------- |",
      "| VBA Macros      | Yes   | RISK    |",
      "| Encrypted       | No    | none    |",
      "| External Links  | Yes   | RISK    |",
    ].join("\n");

    const result = parseOleidOutput(output);
    expect(result.parsed).toBe(true);
    expect(result.metadata.indicators).toBeDefined();
    expect(result.findings.length).toBe(2);
    expect(result.findings[0].severity).toBe("high");
  });

  it("parses key-value format detecting macros", () => {
    const output = "VBA Macros : Yes\nEncrypted : No";
    const result = parseOleidOutput(output);
    expect(result.parsed).toBe(true);
    expect(result.findings).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ category: "macro", severity: "high" }),
      ])
    );
  });

  it("detects encryption indicator", () => {
    const output = "Encrypted : True";
    const result = parseOleidOutput(output);
    expect(result.parsed).toBe(true);
    expect(result.findings).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ category: "encryption", severity: "medium" }),
      ])
    );
  });

  it("detects external relationships", () => {
    const output = "External links : Yes";
    const result = parseOleidOutput(output);
    expect(result.parsed).toBe(true);
    expect(result.findings).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ category: "external-link", severity: "high" }),
      ])
    );
  });

  it("returns unparsed for empty output", () => {
    const result = parseOleidOutput("");
    expect(result.parsed).toBe(false);
  });
});
