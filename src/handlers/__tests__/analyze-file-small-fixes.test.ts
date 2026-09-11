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
