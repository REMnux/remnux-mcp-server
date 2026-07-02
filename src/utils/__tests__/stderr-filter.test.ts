import { describe, it, expect } from "vitest";
import { filterStderrNoise } from "../stderr-filter.js";

describe("filterStderrNoise", () => {
  it("strips webcrack per-transform debug logs", () => {
    const stderr = [
      "2026-07-02T18:39:34.107Z webcrack:transforms prepare: started",
      "2026-07-02T18:39:34.113Z webcrack:transforms prepare: finished with 0 changes",
      "2026-07-02T18:39:34.119Z webcrack:deobfuscate String Array: no",
    ].join("\n");
    expect(filterStderrNoise(stderr)).toBe("");
  });

  it("preserves real webcrack errors while stripping its debug noise", () => {
    const stderr = [
      "2026-07-02T18:39:34.107Z webcrack:transforms prepare: started",
      "output directory already exists",
    ].join("\n");
    const filtered = filterStderrNoise(stderr);
    expect(filtered).toContain("output directory already exists");
    expect(filtered).not.toContain("webcrack:transforms");
  });

  it("preserves Node crash traces (e.g., webcrack on UTF-16 input)", () => {
    const stderr = [
      "2026-07-02T18:39:34.107Z webcrack:transforms prepare: started",
      "SyntaxError: Unexpected character",
      "    at parse (/usr/lib/node_modules/webcrack/dist/index.js:10:5)",
    ].join("\n");
    const filtered = filterStderrNoise(stderr);
    expect(filtered).toContain("SyntaxError: Unexpected character");
  });

  it("strips webcrack debug logs in the TTY (+12ms) format too", () => {
    const stderr = [
      "  webcrack:transforms prepare: started +0ms",
      "  webcrack:deobfuscate String Array: no +6ms",
    ].join("\n");
    expect(filterStderrNoise(stderr)).toBe("");
  });

  it("still strips Volatility progress bars", () => {
    expect(filterStderrNoise("Progress:  100.00 PDB scanning finished")).toBe("");
  });
});
