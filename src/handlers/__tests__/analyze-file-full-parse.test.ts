/**
 * Parsers read a tool's complete output, not the display copy that is cut to the
 * tool's budget. capa's JSON is routinely larger than its 30 KB budget, and cut JSON
 * does not parse, so every capability was lost.
 */

import { describe, it, expect, vi } from "vitest";
import { handleAnalyzeFile } from "../analyze-file.js";
import { createMockDeps, ok, parseEnvelope } from "./helpers.js";

const RULE_COUNT = 40;

/** capa -j output shaped like the real thing, padded past the 30 KB display budget. */
const CAPA_JSON = JSON.stringify({
  meta: { analysis: { format: "pe" } },
  rules: Object.fromEntries(
    Array.from({ length: RULE_COUNT }, (_, i) => [
      `capability ${i}`,
      { meta: { name: `capability ${i}`, namespace: "host-interaction/test" }, source: "x".repeat(1000) },
    ]),
  ),
});

describe("analyze_file parses complete tool output", () => {
  it("recovers capa findings from JSON larger than its display budget", async () => {
    expect(CAPA_JSON.length).toBeGreaterThan(30 * 1024);
    const deps = createMockDeps();
    vi.mocked(deps.connector.execute).mockResolvedValue(
      ok("/samples/sample.exe: PE32 executable (GUI) Intel 80386, for MS Windows"),
    );
    // pestr's bulk pushes the run past the 32 KB summary threshold.
    const bulk = "section .text loaded at 0x401000\n".repeat(1100);
    vi.mocked(deps.connector.executeShell).mockImplementation(async (cmd: string) =>
      cmd.startsWith("capa") ? ok(CAPA_JSON) : cmd.startsWith("pestr") ? ok(bulk) : ok("clean"),
    );

    const env = parseEnvelope(await handleAnalyzeFile(deps, { file: "sample.exe", depth: "standard" }));
    expect(env.data.mode).toBe("summary");
    const capa = env.data.tools.find((t: { name: string }) => t.name === "capa");
    expect(capa.status).toBe("findings");
    expect(capa.finding_count).toBe(RULE_COUNT);
    expect(env.data.triage_summary).toContain("Notable capabilities identified");
  });
});
