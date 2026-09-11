/**
 * 1768.py parser. Layouts are measured from 1768.py 0.0.23; every value here is
 * synthetic (documentation-range address, made-up license ID).
 */

import { describe, it, expect } from "vitest";
import { parse1768Output } from "../1768.js";
import { hasParser } from "../index.js";

const PATH = "/samples/s.bin";

/** The configuration lines as 1768 prints them, ending in its sanity verdict. */
const CONFIG = (verdict = "OK") => [
  "xorkey(chain): 0x11223344",
  "length: 0x00001000",
  "0x0001 payload type                     0x0001 0x0002 0 windows-beacon_http-reverse_http",
  "0x0002 port                             0x0001 0x0002 8080",
  "0x0003 sleeptime                        0x0002 0x0004 60000",
  "0x0008 server,get-uri                   0x0003 0x0100 '203.0.113.10,/pixel.gif'",
  "0x000a post-uri                         0x0003 0x0040 '/submit.php'",
  "0x000b Malleable_C2_Instructions        0x0003 0x0100",
  "  Transform Input: [7:Input,4]",
  "   Print",
  "0x0025 license-id                       0x0002 0x0004 123456789",
  "0x004c                                  0x0002 0x0004 16",
  "0x0000",
  "Guessing Cobalt Strike version: 4.4 (max 0x004c)",
  `Sanity check Cobalt Strike config: ${verdict}`,
];
const BEACON = (verdict = "OK") => [`File: ${PATH}`, ...CONFIG(verdict)].join("\n");

const config = (r: ReturnType<typeof parse1768Output>) =>
  r.findings.find((f) => f.category === "cobalt-strike-config");

describe("parse1768Output", () => {
  it("is registered", () => {
    expect(hasParser("1768")).toBe(true);
  });

  it("rates a configuration that passed 1768's sanity check high", () => {
    const r = parse1768Output(BEACON());
    expect(config(r)?.severity).toBe("high");
    expect(config(r)?.description).toContain("sanity check: OK");
    expect(r.metadata.tool_reported_error).toBeUndefined();
  });

  it("rates a configuration that failed the sanity check low", () => {
    expect(config(parse1768Output(BEACON("NOK")))?.severity).toBe("low");
  });

  it("rates configuration entries with no recognized verdict medium", () => {
    const noVerdict = BEACON().replace(/\nSanity check.*$/, "");
    expect(config(parse1768Output(noVerdict))?.severity).toBe("medium");
  });

  it("lifts the pivot settings, keyed by Cobalt Strike's setting number", () => {
    const settings = parse1768Output(BEACON()).findings.filter((f) => f.category === "cobalt-strike-setting");
    expect(settings.map((f) => f.description)).toEqual([
      "Cobalt Strike setting payload type (0x0001): 0 windows-beacon_http-reverse_http",
      "Cobalt Strike setting port (0x0002): 8080",
      "Cobalt Strike setting server,get-uri (0x0008): '203.0.113.10,/pixel.gif'",
      "Cobalt Strike setting post-uri (0x000a): '/submit.php'",
      "Cobalt Strike setting license-id (0x0025): 123456789",
    ]);
    expect(settings.every((f) => f.severity === "info")).toBe(true);
  });

  it("still labels a setting whose display name a later release changed", () => {
    const renamed = BEACON().replace("0x0008 server,get-uri    ", "0x0008 c2-endpoint        ");
    expect(parse1768Output(renamed).findings.some((f) => f.description.startsWith("Cobalt Strike setting c2-endpoint (0x0008)"))).toBe(true);
  });

  it("says when setting values beyond its bound were not listed", () => {
    const extra = Array.from({ length: 20 }, (_, i) => `0x0025 license-id                       0x0002 0x0004 ${1000 + i}`);
    const r = parse1768Output([`File: ${PATH}`, ...extra, ...CONFIG()].join("\n"));
    expect(r.findings.filter((f) => f.category === "cobalt-strike-setting")).toHaveLength(15);
    expect(config(r)?.evidence).toMatch(/more setting values not listed/);
  });

  it("ignores a sanity check about something other than a Cobalt Strike config", () => {
    const r = parse1768Output(`File: ${PATH}\nSanity check payload: OK\n`);
    expect(r.findings).toEqual([]);
  });

  describe("tool-reported failure (1768 always exits 0)", () => {
    it("reads a probe error on stdout as no configuration, not as a failure", () => {
      const r = parse1768Output(`File: ${PATH}\npayloadType: 0x41424344\npayloadSize: 0x45464748\nError: payload size too large: 0x45464748\n.data section size: 0x000003d0\n`);
      expect(r.metadata.tool_reported_error).toBeUndefined();
      expect(r.metadata.parse_error).toBeUndefined();
      expect(r.findings).toEqual([]);
    });

    it("recognizes a file 1768 could not open, which it reports only on stderr", () => {
      const stderr = `Error opening file ${PATH}\n[Errno 13] Permission denied: '${PATH}'\nNumber of errors: 1`;
      // analyze_file hands the parser stderr when stdout is empty.
      for (const raw of ["", stderr]) {
        const r = parse1768Output(raw, { stderr });
        expect(r.metadata.tool_reported_error).toBe(true);
        expect(r.metadata.parse_error).toBeUndefined();
      }
    });

    it("recovers a configuration after an earlier probe error, without flagging a failure", () => {
      const r = parse1768Output(BEACON().replace("xorkey(chain)", "Error: payload size too large: 0x45464748\nSkipping 32 bytes\nxorkey(chain)"));
      expect(r.metadata.tool_reported_error).toBeUndefined();
      expect(config(r)?.severity).toBe("high");
    });

    it("flags a failure on stderr even when stdout carries a report", () => {
      const r = parse1768Output(`File: ${PATH}\n`, { stderr: "Traceback (most recent call last):\n  File \"1768.py\"" });
      expect(r.metadata.tool_reported_error).toBe(true);
    });

    it("does not read a warning that merely mentions errors as a failure", () => {
      const r = parse1768Output(`File: ${PATH}\n`, { stderr: "UserWarning: error recovery enabled" });
      expect(r.metadata.tool_reported_error).toBeUndefined();
    });

    it("reports a quiet non-beacon run as nothing, not as an error", () => {
      const r = parse1768Output(`File: ${PATH}\npayloadType: 0x00000000\npayloadSize: 0x00000000\nMZ header not found, truncated dump:\n00000000: 00 00 00 00  ....\n`);
      expect(r.findings).toEqual([]);
      expect(r.metadata.tool_reported_error).toBeUndefined();
      expect(r.metadata.parse_error).toBeUndefined();
    });
  });

  it("flags output it cannot read: empty with no failure report, or without a File: header", () => {
    expect(parse1768Output("", { stderr: "" }).metadata.parse_error).toBe(true);
    expect(parse1768Output("some other format\n").metadata.parse_error).toBe(true);
  });
});
