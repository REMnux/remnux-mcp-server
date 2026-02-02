import { describe, it, expect } from "vitest";
import { parsePeframeOutput } from "../peframe.js";

describe("parsePeframeOutput", () => {
  it("detects packer from packer section", () => {
    const output = "packer\n  UPX 3.96";
    const result = parsePeframeOutput(output);
    expect(result.parsed).toBe(true);
    expect(result.metadata.packer).toBe("UPX 3.96");
    expect(result.findings).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ category: "packer", severity: "medium" }),
      ])
    );
  });

  it("detects suspicious imports", () => {
    const output = "imports\n  VirtualAlloc\n  CreateRemoteThread\n  WriteProcessMemory";
    const result = parsePeframeOutput(output);
    expect(result.parsed).toBe(true);
    const importFindings = result.findings.filter((f) => f.category === "notable-import");
    expect(importFindings.length).toBe(3);
  });

  it("detects suspicious strings in strings section", () => {
    const output = "strings\n  http://evil.com/payload.exe\n  C:\\Windows\\temp\\dropper.bat";
    const result = parsePeframeOutput(output);
    expect(result.parsed).toBe(true);
    const stringFindings = result.findings.filter((f) => f.category === "notable-string");
    expect(stringFindings.length).toBeGreaterThanOrEqual(1);
  });

  it("ignores section divider lines like '--- Packer ---'", () => {
    const output = "--- Packer ---\nNone\n--- Strings ---\ntest";
    const result = parsePeframeOutput(output);
    const packerFindings = result.findings.filter((f) => f.category === "packer");
    expect(packerFindings.length).toBe(0);
  });

  it("ignores Unicode box-drawing dividers (━━━)", () => {
    const output = "packer\n━━━━━━━━━━━━━━━━━━━━\nUPX 3.96";
    const result = parsePeframeOutput(output);
    expect(result.parsed).toBe(true);
    expect(result.metadata.packer).toBe("UPX 3.96");
  });

  it("does not treat 'features packer' as a packer finding", () => {
    const output = "packer\n  features    packer\n  None";
    const result = parsePeframeOutput(output);
    const packerFindings = result.findings.filter((f) => f.category === "packer");
    expect(packerFindings.length).toBe(0);
  });

  it("does not false-positive on lines containing 'packer' outside packer section", () => {
    const output = "file\n  features    packer\nstrings\n  test_packed_string";
    const result = parsePeframeOutput(output);
    const packerFindings = result.findings.filter((f) => f.category === "packer");
    expect(packerFindings.length).toBe(0);
  });

  it("returns unparsed when no findings", () => {
    const output = "file\n  normal_app.exe\n  Size: 1234";
    const result = parsePeframeOutput(output);
    expect(result.parsed).toBe(false);
    expect(result.findings).toHaveLength(0);
  });
});
