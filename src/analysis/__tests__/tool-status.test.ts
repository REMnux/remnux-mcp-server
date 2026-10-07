import { describe, it, expect, vi } from "vitest";
import { generateSummary } from "../summarizer.js";
import { parseCapaOutput } from "../../parsers/capa.js";
import { parseDiecOutput } from "../../parsers/diec.js";
import { handleAnalyzeFile } from "../../handlers/analyze-file.js";
import { createMockDeps, ok, parseEnvelope } from "../../handlers/__tests__/helpers.js";
import { exitCodeIsFailure } from "../../tools/registry.js";

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

  it("reads a result exit code as a result and a failure exit code as an error", () => {
    // xorsearch exits with its score, and with 255 when it fails.
    expect(statusOf({ name: "xorsearch", exit_code: 10 }).status).toBe("not_assessed");
    expect(statusOf({ name: "xorsearch", exit_code: 255 }).status).toBe("error");
  });

  it("reads a non-zero exit the handler judged a result as a result", () => {
    expect(statusOf({ name: "upx-decompress", exit_code: 2, exit_is_result: true }).status).toBe("not_assessed");
    expect(statusOf({ name: "upx-decompress", exit_code: 2 }).status).toBe("error");
  });
});

const NOT_AUTOIT =
  "ERROR:autoit_ripper.autoit_unpack:Couldn't find the EA05 location chunk in binary\n" +
  "ERROR:autoit_ripper.autoit_unpack:Couldn't find any appropiate PE resource directory\n" +
  "ERROR:autoit_ripper.autoit_unpack:Couldn't find the script resource\n" +
  "ERROR:autoit_ripper.autoit_unpack:Couldn't find the JB01 location chunk in binary";
const UPX_BANNER =
  "                       Ultimate Packer for eXecutables\n" +
  "        File size         Ratio      Format      Name\n" +
  "   --------------------   ------   -----------   -----------\n\nUnpacked 0 files.";
const UPX_NOT_PACKED = "upx: /samples/sample.exe: NotPackedException: not packed by UPX";

describe("exit codes that report a result, judged from complete output", () => {
  it("autoit-ripper exit 1 is a result only when every line is a 'no script here' message", () => {
    expect(exitCodeIsFailure("autoit-ripper", 1, `\n${NOT_AUTOIT}`)).toBe(false);
    // A PE without a resource section takes the EA06 path's "no resources" message instead.
    expect(exitCodeIsFailure("autoit-ripper", 1,
      "ERROR:autoit_ripper.autoit_unpack:Couldn't find the EA05 location chunk in binary\n" +
      "ERROR:autoit_ripper.autoit_unpack:The input file has no resources\n" +
      "ERROR:autoit_ripper.autoit_unpack:Couldn't find the JB01 location chunk in binary")).toBe(false);
    expect(exitCodeIsFailure("autoit-ripper", 1,
      `${NOT_AUTOIT}\nERROR:autoit_ripper.autoit_unpack:Couldn't decode the autoit script`)).toBe(true);
    expect(exitCodeIsFailure("autoit-ripper", 1,
      "ERROR:autoit_ripper.autoit_unpack:Failed to parse the input file")).toBe(true);
    expect(exitCodeIsFailure("autoit-ripper", 1, `${NOT_AUTOIT}\nERROR:autoit_ripper.autoit_unpack:CRC data mismatch`)).toBe(true);
    expect(exitCodeIsFailure("autoit-ripper", 1, `${NOT_AUTOIT}\nTraceback (most recent call last):\nRuntimeError: boom`)).toBe(true);
    expect(exitCodeIsFailure("autoit-ripper", 1, "AutoIt-Ripper banner\n" + NOT_AUTOIT)).toBe(true);
    expect(exitCodeIsFailure("autoit-ripper", 1, "\n")).toBe(true);
    expect(exitCodeIsFailure("autoit-ripper", 2, NOT_AUTOIT)).toBe(true);
    expect(exitCodeIsFailure("autoit-ripper", 1)).toBe(true);
  });

  it("upx exit 2 is a result only with NotPackedException; every other exit is a failure", () => {
    expect(exitCodeIsFailure("upx-decompress", 2, `${UPX_BANNER}\n${UPX_NOT_PACKED}`)).toBe(false);
    expect(exitCodeIsFailure("upx-decompress", 2, `${UPX_BANNER}\nupx: /samples/sample.exe: CantUnpackException: header corrupted`)).toBe(true);
    expect(exitCodeIsFailure("upx-decompress", 139, `${UPX_BANNER}\n${UPX_NOT_PACKED}`)).toBe(true);
    expect(exitCodeIsFailure("upx-decompress", 1, "upx: /samples/x.exe: FileNotFoundException")).toBe(true);
    expect(exitCodeIsFailure("upx-decompress", 127)).toBe(true);
    // A filename may contain the matched words or a newline. Neither can hide another error.
    expect(exitCodeIsFailure("upx-decompress", 2,
      `${UPX_BANNER}\nupx: /samples/error report.exe: NotPackedException: not packed by UPX`)).toBe(false);
    expect(exitCodeIsFailure("upx-decompress", 2,
      `${UPX_BANNER}\nupx: /samples/x: NotPackedException: not packed by UPX\nrest.exe: CantUnpackException: header corrupted`)).toBe(true);
  });

  it("does not apply one tool's result output to another tool", () => {
    expect(exitCodeIsFailure("pestr", 1, NOT_AUTOIT)).toBe(true);
    expect(exitCodeIsFailure("pestr", 2, UPX_NOT_PACKED)).toBe(true);
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

  // Runs a standard-depth analysis where autoit-ripper and upx return the given results.
  async function statusesWith(
    autoit: { stdout: string; stderr: string; exitCode: number },
    upx: { stdout: string; stderr: string; exitCode: number },
  ) {
    const deps = createMockDeps();
    vi.mocked(deps.connector.execute).mockResolvedValue(
      ok("/samples/sample.exe: PE32 executable (GUI) Intel 80386, for MS Windows"),
    );
    const bulk = "section .text loaded at 0x401000\n".repeat(1100);
    vi.mocked(deps.connector.executeShell).mockImplementation(async (cmd: string) =>
      cmd.startsWith("autoit-ripper") ? autoit
        : cmd.startsWith("upx") ? upx
          : cmd.startsWith("pestr") ? ok(bulk) : ok("done"),
    );
    const env = parseEnvelope(await handleAnalyzeFile(deps, { file: "sample.exe", depth: "standard" }));
    expect(env.data.mode).toBe("summary");
    const statusOfTool = (name: string) =>
      env.data.tools.find((t: { name: string }) => t.name === name)?.status;
    return { autoit: statusOfTool("autoit-ripper"), upx: statusOfTool("upx-decompress") };
  }

  it("reports a PE that is neither AutoIt nor UPX-packed without errors for either tool", async () => {
    const s = await statusesWith(
      { stdout: "", stderr: NOT_AUTOIT, exitCode: 1 },
      { stdout: UPX_BANNER, stderr: UPX_NOT_PACKED, exitCode: 2 },
    );
    expect(s).toEqual({ autoit: "not_assessed", upx: "not_assessed" });
  });

  it("keeps real failures as errors", async () => {
    const s = await statusesWith(
      { stdout: "", stderr: `${NOT_AUTOIT}\nERROR:autoit_ripper.autoit_unpack:CRC data mismatch`, exitCode: 1 },
      { stdout: UPX_BANNER, stderr: UPX_NOT_PACKED, exitCode: 139 },
    );
    expect(s).toEqual({ autoit: "error", upx: "error" });
  });

  it("judges from complete output, past the display budget and across stdout and stderr", async () => {
    // A traceback beyond the per-tool display budget still marks the run as failed.
    const longThenCrash =
      `${NOT_AUTOIT}\n`.repeat(400) + "Traceback (most recent call last):\nRuntimeError: boom";
    const s = await statusesWith(
      { stdout: "", stderr: longThenCrash, exitCode: 1 },
      // stdout is not empty, so the display copy drops stderr, which holds NotPackedException.
      { stdout: UPX_BANNER, stderr: UPX_NOT_PACKED, exitCode: 2 },
    );
    expect(longThenCrash.length).toBeGreaterThan(64 * 1024);
    expect(s).toEqual({ autoit: "error", upx: "not_assessed" });
  });

  it("judges from unfiltered stderr, so the noise filter cannot add or remove a diagnostic", async () => {
    // The noise filter drops any line containing "This version of" or "requires Python".
    const s = await statusesWith(
      { stdout: "", stderr: `${NOT_AUTOIT}\nERROR:autoit_ripper.autoit_unpack:This version of the script is unsupported`, exitCode: 1 },
      { stdout: UPX_BANNER, stderr: "upx: /samples/requires Python.exe: NotPackedException: not packed by UPX", exitCode: 2 },
    );
    expect(s).toEqual({ autoit: "error", upx: "not_assessed" });
  });
});
