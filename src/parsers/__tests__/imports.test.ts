import { describe, it, expect } from "vitest";
import { parsePeImports, apiPresent } from "../imports.js";

function readpeJson(libs: Array<{ Name: string; Functions: Array<{ Name: string }> }>) {
  return JSON.stringify({ "Imported functions": libs });
}

describe("parsePeImports", () => {
  it("parses readpe -i -f json into a structured import table", () => {
    const json = readpeJson([
      { Name: "WININET.dll", Functions: [{ Name: "InternetOpenW" }, { Name: "InternetReadFile" }] },
      { Name: "ADVAPI32.dll", Functions: [{ Name: "RegSetValueExW" }] },
    ]);
    const imp = parsePeImports(json);
    expect(imp.parsed).toBe(true);
    expect(imp.count).toBe(3);
    expect(imp.dlls).toHaveLength(2);
    expect(imp.dlls[0]).toEqual({ dll: "WININET.dll", functions: ["InternetOpenW", "InternetReadFile"] });
    // functionSet is lowercased for case-insensitive lookup.
    expect(imp.functionSet.has("internetopenw")).toBe(true);
    expect(imp.functionSet.has("regsetvalueexw")).toBe(true);
  });

  it("treats valid JSON with no import table as parsed-but-empty", () => {
    const imp = parsePeImports(JSON.stringify({ filetype: "PE32" }));
    expect(imp.parsed).toBe(true);
    expect(imp.count).toBe(0);
    expect(imp.functionSet.size).toBe(0);
  });

  it("returns parsed=false on invalid JSON (readpe failure)", () => {
    const imp = parsePeImports("readpe: not a PE file");
    expect(imp.parsed).toBe(false);
    expect(imp.count).toBe(0);
  });

  it("is fail-soft on malformed entries", () => {
    const imp = parsePeImports(
      JSON.stringify({ "Imported functions": [null, 42, { Name: "K.dll", Functions: [null, { Name: "Foo" }, {}] }] }),
    );
    expect(imp.parsed).toBe(true);
    expect(imp.count).toBe(1);
    expect(imp.functionSet.has("foo")).toBe(true);
  });
});

describe("apiPresent", () => {
  const set = new Set(["internetopenurlw", "openclipboard", "getclipboarddata", "regsetvalueexw"]);

  it("matches the base name plus A/W variants", () => {
    expect(apiPresent("InternetOpenUrl", set)).toBe(true); // matched by ...W
    expect(apiPresent("OpenClipboard", set)).toBe(true); // exact
    expect(apiPresent("RegSetValueEx", set)).toBe(true); // matched by ...W
  });

  it("does NOT mangle names that already end in a/w (no stripping)", () => {
    // GetClipboardData ends in 'a' — it must match exactly, not be confused with a suffix.
    expect(apiPresent("GetClipboardData", set)).toBe(true);
    // A required API genuinely absent stays absent.
    expect(apiPresent("SetClipboardData", set)).toBe(false);
  });

  it("returns false for absent APIs", () => {
    expect(apiPresent("VirtualAllocEx", set)).toBe(false);
  });
});
