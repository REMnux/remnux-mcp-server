/**
 * analyze_file's handling of 1768, which exits 0 whether or not it succeeds.
 * Values are synthetic (documentation-range address, made-up license ID).
 */

import { describe, it, expect, vi } from "vitest";
import { handleAnalyzeFile } from "../analyze-file.js";
import { createMockDeps, ok, parseEnvelope } from "./helpers.js";

/** Pushes the run past the 32 KB summary threshold. */
const BULK = "section .text loaded at 0x401000\n".repeat(1100);

type Result = { stdout: string; stderr: string; exitCode: number };

const beacon = (path: string) =>
  ok([
    `File: ${path}`,
    "0x0001 payload type                     0x0001 0x0002 0 windows-beacon_http-reverse_http",
    "0x0002 port                             0x0001 0x0002 8080",
    "0x0008 server,get-uri                   0x0003 0x0100 '203.0.113.10,/pixel.gif'",
    "0x0025 license-id                       0x0002 0x0004 123456789",
    "0x0000",
    "Sanity check Cobalt Strike config: OK",
  ].join("\n"));

async function run(result1768: (path: string) => Result) {
  const deps = createMockDeps();
  vi.mocked(deps.connector.execute).mockResolvedValue(
    ok("/samples/sample.exe: PE32 executable (GUI) Intel 80386, for MS Windows"),
  );
  let command = "";
  vi.mocked(deps.connector.executeShell).mockImplementation(async (cmd: string) => {
    if (cmd.startsWith("1768.py")) {
      command = cmd;
      return result1768(cmd.match(/'([^']+)'/)?.[1] ?? "");
    }
    return cmd.startsWith("pestr") ? ok(BULK) : ok("done");
  });
  const env = parseEnvelope(await handleAnalyzeFile(deps, { file: "sample.exe", depth: "standard" }));
  expect(env.data.mode).toBe("summary");
  const tool = env.data.tools.find((t: { name: string }) => t.name === "1768");
  expect(tool, "1768 must be in the standard PE chain").toBeDefined();
  return { data: env.data, tool, command };
}

describe("analyze_file: 1768", () => {
  it("runs 1768 with its file argument taken literally", async () => {
    const { command } = await run(beacon);
    expect(command).toMatch(/^1768\.py --literalfilenames -n '/);
  });

  it("reports a recovered configuration with its triage token", async () => {
    const { data, tool } = await run(beacon);
    expect(tool.status).toBe("findings");
    expect(tool.key_lines.join("\n")).toContain("sanity check: OK");
    expect(data.triage_summary).toContain("Cobalt Strike configuration recovered (1768)");
  });

  it("reports a probe error on a file without a beacon as clean", async () => {
    const { data, tool } = await run((path) => ok(`File: ${path}\nError: payload size too large: 0x45464748\n`));
    expect(tool.status).toBe("clean");
    expect(tool.tool_reported_error).toBeUndefined();
    expect(data.triage_summary).not.toContain("Cobalt Strike");
  });

  it("reports a file 1768 could not open, which it says only on stderr, as an error", async () => {
    const { tool } = await run((path) => ({
      stdout: "",
      stderr: `Error opening file ${path}\n[Errno 13] Permission denied: '${path}'\nNumber of errors: 1`,
      exitCode: 0,
    }));
    expect(tool).toMatchObject({ status: "error", tool_reported_error: true });
  });
});
