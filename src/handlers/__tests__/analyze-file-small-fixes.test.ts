import { describe, it, expect } from "vitest";
import { generateNextSteps, generateTriageSummary } from "../analyze-file.js";
import { parseFlossOutput } from "../../parsers/floss.js";

describe("suggested_next_steps", () => {
  it("keeps the pointers to this run's results when the generic list is full", () => {
    // A PE with no capa findings already gets five generic steps.
    const steps = generateNextSteps("PE", "standard", [], [], 12);
    expect(steps.some((s) => s.startsWith("Extracted IOCs are in the 'iocs' field"))).toBe(true);
    expect(steps.some((s) => s.startsWith("Draft a report"))).toBe(true);
  });

  const ranTool = (name: string) => ({ name, command: name, output: "", exit_code: 0 });

  it("drops a generic step whose tool this run already executed", () => {
    const pe = generateNextSteps("PE", "standard", [ranTool("upx-decompress"), ranTool("pestr")], [], 0);
    expect(pe.some((s) => s.includes("'upx -d'"))).toBe(false);
    expect(pe.some((s) => s.includes("pestr <file>"))).toBe(false);
    const data = generateNextSteps(
      "DataWithPEExtension", "standard", [ranTool("speakeasy-sc-x86"), ranTool("1768")], [], 0,
    );
    expect(data.some((s) => s.includes("speakeasy"))).toBe(false);
    expect(data.some((s) => s.includes("1768.py"))).toBe(false);
    const ole = generateNextSteps("OLE2", "standard", [ranTool("pcodedmp")], [], 0);
    expect(ole.some((s) => s.includes("pcodedmp"))).toBe(false);
  });

  it("keeps a generic step whose tool did not run", () => {
    const pe = generateNextSteps("PE", "standard", [], [], 0);
    expect(pe.some((s) => s.includes("'upx -d'"))).toBe(true);
    expect(pe.some((s) => s.includes("pestr <file>"))).toBe(true);
    expect(pe.some((s) => s.includes("speakeasy -t <file>"))).toBe(true);
    const data = generateNextSteps("DataWithPEExtension", "standard", [], [], 0);
    expect(data.some((s) => s.includes("1768.py"))).toBe(true);
    // A step that needs arguments the chain never passes stays.
    expect(data.some((s) => s.includes("base64dump.py -n 20"))).toBe(true);
  });
});

describe("triage summary", () => {
  it("counts critical findings", () => {
    const olevba = {
      name: "olevba", command: "olevba x", output: "", exit_code: 0,
      findings: [{ description: "API call", severity: "critical" as const }],
    };
    expect(generateTriageSummary("OOXML", [olevba], 0)).toContain("1 critical-severity finding(s)");
  });

  it("says how many tools ran, without calling failed ones completed", () => {
    const failed = { name: "capa", command: "capa x", output: "error", exit_code: 1 };
    const summary = generateTriageSummary("PE", [failed], 0);
    expect(summary).toContain("1 tool(s) ran");
    expect(summary).not.toContain("completed");
  });
});

describe("floss section headers", () => {
  it("keeps every decoded string after one that reads 'constructor'", () => {
    const out = ["FLOSS DECODED STRINGS", "constructor", "http://a.example/x", "second string"].join("\n");
    expect(parseFlossOutput(out).metadata.string_counts).toMatchObject({ decoded: 3 });
  });
});
