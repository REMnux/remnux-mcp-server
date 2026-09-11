import { describe, it, expect, vi } from "vitest";
import { generateSummary } from "../summarizer.js";
import { parseCapaOutput } from "../../parsers/capa.js";
import { parseDiecOutput } from "../../parsers/diec.js";
import { handleAnalyzeFile } from "../../handlers/analyze-file.js";
import { createMockDeps, ok, parseEnvelope } from "../../handlers/__tests__/helpers.js";

type Run = Parameters<typeof generateSummary>[5][number];

const statusOf = (tool: Partial<Run> & { name: string }) =>
  generateSummary(
    "x.exe", "PE32", "PE", "standard", "triage",
    [{ command: "x", output: "some output", exit_code: 0, ...tool }],
    [], [], [], [], {} as never, [], "guidance",
  ).tools[0];

describe("summary tool status", () => {
  it("reports a tool with no parser as not_assessed", () => {
    expect(statusOf({ name: "pestr" }).status).toBe("not_assessed");
  });

  it("reports a parsed tool that resolved nothing as clean", () => {
    expect(statusOf({ name: "capa" }).status).toBe("clean");
  });

  it("reports findings", () => {
    expect(statusOf({ name: "capa", findings: [{ description: "x" }] }).status).toBe("findings");
  });

  it("reports a parser that could not read the output as an error", () => {
    const tool = statusOf({ name: "capa", parse_failed: true });
    expect(tool.status).toBe("error");
    expect(tool.parse_failed).toBe(true);
  });

  it("reports a non-zero exit as an error whether or not a parser exists", () => {
    expect(statusOf({ name: "pestr", exit_code: 1 }).status).toBe("error");
    expect(statusOf({ name: "capa", exit_code: 1 }).status).toBe("error");
  });
});

describe("capa and diec mark output they cannot read", () => {
  it("capa marks JSON that does not parse", () => {
    expect(parseCapaOutput('{"rules": {').metadata.parse_error).toBe(true);
    expect(parseCapaOutput('{"rules": {}}').metadata.parse_error).toBeUndefined();
  });

  it("diec marks output that carries no JSON", () => {
    expect(parseDiecOutput("PE32\n    Packer: UPX").metadata.parse_error).toBe(true);
    expect(parseDiecOutput('{"detects": []}').metadata.parse_error).toBeUndefined();
  });
});

describe("analyze_file status end to end", () => {
  it("reports unreadable capa output as an error and unparsed tools as not_assessed", async () => {
    const deps = createMockDeps();
    vi.mocked(deps.connector.execute).mockResolvedValue(
      ok("/samples/sample.exe: PE32 executable (GUI) Intel 80386, for MS Windows"),
    );
    // pestr's bulk pushes the run past the 32 KB summary threshold.
    const bulk = "section .text loaded at 0x401000\n".repeat(1100);
    vi.mocked(deps.connector.executeShell).mockImplementation(async (cmd: string) =>
      cmd.startsWith("capa") ? ok('{"rules": {"cut') : cmd.startsWith("pestr") ? ok(bulk) : ok("done"),
    );
    const env = parseEnvelope(await handleAnalyzeFile(deps, { file: "sample.exe", depth: "standard" }));
    expect(env.data.mode).toBe("summary");
    const byName = (name: string) => env.data.tools.find((t: { name: string }) => t.name === name);
    expect(byName("capa")).toMatchObject({ status: "error", parse_failed: true });
    expect(byName("pestr").status).toBe("not_assessed");
  });

  it("reports a tool that refused the file as an error, not as a parser failure", async () => {
    const deps = createMockDeps();
    vi.mocked(deps.connector.execute).mockResolvedValue(
      ok("/samples/sample.exe: PE32 executable (GUI) Intel 80386, for MS Windows"),
    );
    const bulk = "section .text loaded at 0x401000\n".repeat(1100);
    vi.mocked(deps.connector.executeShell).mockImplementation(async (cmd: string) =>
      cmd.startsWith("capa")
        ? { stdout: "", stderr: "ERROR capa: input file does not appear to be a supported file", exitCode: 16 }
        : cmd.startsWith("pestr") ? ok(bulk) : ok("done"),
    );
    const env = parseEnvelope(await handleAnalyzeFile(deps, { file: "sample.exe", depth: "standard" }));
    const capa = env.data.tools.find((t: { name: string }) => t.name === "capa");
    expect(capa.status).toBe("error");
    expect(capa.parse_failed).toBeUndefined();
  });
});
