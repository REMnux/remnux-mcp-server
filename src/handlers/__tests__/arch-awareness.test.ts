/**
 * Architecture awareness across handlers: on stock arm64 REMnux some tools are
 * absent, and the server says so; on amd64 its output is unchanged. Each test
 * builds a fresh mock connector, because the target architecture is cached per
 * connector.
 */
import { describe, it, expect, vi } from "vitest";
import { handleDownloadFile } from "../download-file.js";
import { handleCheckTools } from "../check-tools.js";
import { handleGetToolHelp } from "../get-tool-help.js";
import { handleGetServerInfo } from "../get-server-info.js";
import { handleRunTool } from "../run-tool.js";
import { handleSuggestTools } from "../suggest-tools.js";
import { handleAnalyzeFile } from "../analyze-file.js";
import { handleDownloadFromUrl } from "../download-from-url.js";
import { createMockDeps, ok, parseEnvelope } from "./helpers.js";
import type { HandlerDeps } from "../types.js";

vi.mock("fs", async (importOriginal) => {
  const actual = await importOriginal<typeof import("fs")>();
  return {
    ...actual,
    existsSync: vi.fn((p: string) => p.startsWith("/tmp")),
    statSync: vi.fn(() => ({ isDirectory: () => true })),
  };
});

const ARCH_PROBE = "dpkg --print-architecture 2>/dev/null || uname -m";

/**
 * A target that answers like bash on REMnux: the architecture probe, `command -v`,
 * the `which` batches suggest_tools and check_tools send, and a missing command
 * with exit 127 and bash's message. Anything else succeeds with `output`.
 */
function target(deps: HandlerDeps, arch: string | null, missing: string[], output = "tool output") {
  const absent = new Set(missing);
  vi.mocked(deps.connector.executeShell).mockImplementation(async (cmd: string) => {
    if (cmd === ARCH_PROBE) return arch ? ok(`${arch}\n`) : { stdout: "", stderr: "", exitCode: 1 };
    const probe = cmd.match(/^command -v (\S+)$/);
    if (probe) return absent.has(probe[1]) ? { stdout: "", stderr: "", exitCode: 1 } : ok(`/usr/bin/${probe[1]}\n`);
    if (cmd.includes("which ")) {
      const names = [...cmd.matchAll(/which (\S+)/g)].map((m) => m[1]).filter((n) => !absent.has(n));
      // suggest_tools echoes each found name; check_tools prints which's path.
      return ok(names.map((n) => (cmd.includes("echo") ? n : `/usr/bin/${n}`)).join("\n"));
    }
    const missingHere = [...absent].find((name) => new RegExp(`(^|[\\s/'"])${name.replace(/\./g, "\\.")}(\\s|$)`).test(cmd));
    if (missingHere) return { stdout: "", stderr: `bash: line 1: ${missingHere}: command not found`, exitCode: 127 };
    return ok(output);
  });
}

describe("download_file re-archives a file extracted from a .rar", () => {
  function depsWithRarProvenance() {
    // These cases cover the rar fallback, not path confinement: without the sandbox the
    // mocked /tmp output_path needs no ingest root.
    const deps = createMockDeps({ noSandbox: true });
    deps.sessionState.storeArchiveInfo("sample.rar", ["sample.bin"], "rar", "infected");
    vi.mocked(deps.connector.execute).mockImplementation(async (cmd: string[]) => {
      if (cmd[0] === "stat") return ok("1024");
      if (cmd[0] === "sha256sum") return ok("abc123  /output/sample.bin");
      return ok("");
    });
    vi.mocked(deps.connector.readFileToPath).mockResolvedValue(undefined);
    return deps;
  }

  it("uses rar when the target has it (unchanged)", async () => {
    const deps = depsWithRarProvenance();
    target(deps, "amd64", []);
    const env = parseEnvelope(await handleDownloadFile(deps, { file_path: "sample.bin", output_path: "/tmp/dl" }));
    expect(env.data.archive_format).toBe("rar");
    expect(env.data.host_path).toBe("/tmp/dl/sample.bin.rar");
    expect(env.data.note).toBeUndefined();
    const archiveCall = vi.mocked(deps.connector.execute).mock.calls.find((c) => c[0][0] === "rar");
    expect(archiveCall?.[0]).toEqual(["rar", "a", "-pinfected", "-hp", expect.stringMatching(/sample\.bin\.rar$/), "/output/sample.bin"]);
  });

  it("falls back to 7z with encrypted names and the same password when rar is absent", async () => {
    const deps = depsWithRarProvenance();
    target(deps, "arm64", ["rar"]);
    const env = parseEnvelope(await handleDownloadFile(deps, { file_path: "sample.bin", output_path: "/tmp/dl" }));
    expect(env.success).toBe(true);
    expect(env.data.archived).toBe(true);
    expect(env.data.archive_format).toBe("7z");
    expect(env.data.archive_password).toBe("infected");
    expect(env.data.host_path).toBe("/tmp/dl/sample.bin.7z");
    expect(env.data.note).toMatch(/rar is not installed/);
    const calls = vi.mocked(deps.connector.execute).mock.calls.map((c) => c[0]);
    expect(calls.some((c) => c[0] === "rar")).toBe(false);
    expect(calls.find((c) => c[0] === "7z")).toEqual(["7z", "a", "-pinfected", "-mhe=on", expect.stringMatching(/sample\.bin\.7z$/), "/output/sample.bin"]);
    // The extraction record is untouched: it describes where the file came from.
    expect(deps.sessionState.getArchiveInfo("sample.bin")?.format).toBe("rar");
  });

  it("keeps rar when the presence probe cannot answer, so a failure stays visible", async () => {
    const deps = depsWithRarProvenance();
    vi.mocked(deps.connector.executeShell).mockRejectedValue(new Error("Command timed out after 10 seconds"));
    const env = parseEnvelope(await handleDownloadFile(deps, { file_path: "sample.bin", output_path: "/tmp/dl" }));
    expect(env.data.archive_format).toBe("rar");
  });

  it("reports a genuine archiver failure without steering a sample to a raw download", async () => {
    const deps = depsWithRarProvenance();
    target(deps, "amd64", []);
    vi.mocked(deps.connector.execute).mockImplementation(async (cmd: string[]) => {
      if (cmd[0] === "stat") return ok("1024");
      if (cmd[0] === "sha256sum") return ok("abc123  /output/sample.bin");
      if (cmd[0] === "rar") return { stdout: "", stderr: "Cannot create archive", exitCode: 2 };
      return ok("");
    });
    const env = parseEnvelope(await handleDownloadFile(deps, { file_path: "sample.bin", output_path: "/tmp/dl" }));
    expect(env.success).toBe(false);
    expect(env.error_code).toBe("ARCHIVE_FAILED");
    expect(env.remediation).toMatch(/keep it archived/);
    expect(env.remediation).toMatch(/only for harmless files/);
  });

  it("reports a failing 7z fallback without steering a sample to a raw download", async () => {
    const deps = depsWithRarProvenance();
    target(deps, "arm64", ["rar"]);
    vi.mocked(deps.connector.execute).mockImplementation(async (cmd: string[]) => {
      if (cmd[0] === "stat") return ok("1024");
      if (cmd[0] === "sha256sum") return ok("abc123  /output/sample.bin");
      if (cmd[0] === "7z") return { stdout: "", stderr: "System ERROR: Not enough space", exitCode: 2 };
      return ok("");
    });
    const env = parseEnvelope(await handleDownloadFile(deps, { file_path: "sample.bin", output_path: "/tmp/dl" }));
    expect(env.error_code).toBe("ARCHIVE_FAILED");
    expect(env.remediation).toMatch(/keep it archived/);
  });

  it("does not probe for rar when the format is zip", async () => {
    const deps = createMockDeps({ noSandbox: true });
    target(deps, "arm64", ["rar"]);
    vi.mocked(deps.connector.execute).mockImplementation(async (cmd: string[]) => {
      if (cmd[0] === "stat") return ok("1024");
      if (cmd[0] === "sha256sum") return ok("abc123  /output/report.txt");
      return ok("");
    });
    vi.mocked(deps.connector.readFileToPath).mockResolvedValue(undefined);
    const env = parseEnvelope(await handleDownloadFile(deps, { file_path: "report.txt", output_path: "/tmp/dl" }));
    expect(env.data.archive_format).toBe("zip");
    expect(deps.connector.executeShell).not.toHaveBeenCalled();
  });
});

describe("get_server_info", () => {
  it("reports the target's architecture", async () => {
    const deps = createMockDeps();
    target(deps, "arm64", []);
    const env = parseEnvelope(await handleGetServerInfo(deps, "9.9.9"));
    expect(env.data.architecture).toBe("arm64");
  });

  it("reports null when the target cannot say", async () => {
    const deps = createMockDeps();
    vi.mocked(deps.connector.executeShell).mockRejectedValue(new Error("down"));
    const env = parseEnvelope(await handleGetServerInfo(deps, "9.9.9"));
    expect(env.data.architecture).toBeNull();
  });
});

describe("check_tools", () => {
  it("explains registry tools stock arm64 REMnux omits, and only those", async () => {
    const deps = createMockDeps();
    target(deps, "arm64", ["tracesc", "js_unshroud", "peframe"]);
    const env = parseEnvelope(await handleCheckTools(deps));
    expect(env.data.summary.architecture).toBe("arm64");
    const byName = Object.fromEntries(env.data.tools.map((t: { tool: string }) => [t.tool, t]));
    expect(byName.tracesc).toMatchObject({ available: false, note: expect.stringMatching(/^Not included in stock arm64 REMnux/) });
    expect(byName.js_unshroud.note).toMatch(/^Not included in stock arm64 REMnux/);
    // Missing for some other reason: no architecture excuse.
    expect(byName.peframe).toEqual({ tool: "peframe", available: false });
  });

  it("adds no notes on amd64", async () => {
    const deps = createMockDeps();
    target(deps, "amd64", ["tracesc"]);
    const env = parseEnvelope(await handleCheckTools(deps));
    expect(env.data.summary.architecture).toBe("amd64");
    expect(env.data.tools.find((t: { tool: string }) => t.tool === "tracesc")).toEqual({ tool: "tracesc", available: false });
  });
});

describe("get_tool_help", () => {
  it("explains a missing tool that stock arm64 REMnux omits", async () => {
    const deps = createMockDeps();
    target(deps, "arm64", []);
    vi.mocked(deps.connector.execute).mockResolvedValue({ stdout: "", stderr: "", exitCode: 127 });
    const env = parseEnvelope(await handleGetToolHelp(deps, { tool: "trid" }));
    expect(env.error_code).toBe("NOT_FOUND");
    expect(env.error).toMatch(/Tool 'trid' not found\. It may not be installed on this REMnux system\. Not included in stock arm64 REMnux/);
  });

  it("explains a missing tool in local mode, where spawn reports ENOENT", async () => {
    const deps = createMockDeps({ mode: "local" });
    target(deps, "arm64", []);
    vi.mocked(deps.connector.execute).mockRejectedValue(new Error("spawn trid ENOENT"));
    const env = parseEnvelope(await handleGetToolHelp(deps, { tool: "trid" }));
    expect(env.error_code).toBe("NOT_FOUND");
    expect(env.error).toMatch(/Not included in stock arm64 REMnux/);
  });

  it("does not blame the tool when the shell named a missing helper it calls", async () => {
    const deps = createMockDeps();
    target(deps, "arm64", []);
    vi.mocked(deps.connector.execute).mockResolvedValue({
      stdout: "", stderr: "/usr/local/bin/trid: line 3: helper_xyz: command not found", exitCode: 127,
    });
    const env = parseEnvelope(await handleGetToolHelp(deps, { tool: "trid" }));
    expect(env.error_code).toBe("NOT_FOUND");
    expect(env.error).toBe("Tool 'trid' not found. It may not be installed on this REMnux system.");
  });

  it("keeps the plain message on amd64 and for tools that are the same on every architecture", async () => {
    const amd = createMockDeps();
    target(amd, "amd64", []);
    vi.mocked(amd.connector.execute).mockResolvedValue({ stdout: "", stderr: "", exitCode: 127 });
    expect(parseEnvelope(await handleGetToolHelp(amd, { tool: "trid" })).error).toBe(
      "Tool 'trid' not found. It may not be installed on this REMnux system.",
    );
    const arm = createMockDeps();
    target(arm, "arm64", []);
    vi.mocked(arm.connector.execute).mockResolvedValue({ stdout: "", stderr: "", exitCode: 127 });
    expect(parseEnvelope(await handleGetToolHelp(arm, { tool: "capa" })).error).toBe(
      "Tool 'capa' not found. It may not be installed on this REMnux system.",
    );
    expect(arm.connector.executeShell).not.toHaveBeenCalled();
  });
});

describe("run_tool", () => {
  it("adds an output advisory for a missing command stock arm64 REMnux omits", async () => {
    const deps = createMockDeps();
    target(deps, "arm64", ["trid"]);
    const env = parseEnvelope(await handleRunTool(deps, { command: "trid /home/remnux/files/samples/x.bin" }));
    expect(env.data.exit_code).toBe(127);
    expect(env.data.output_advisory).toMatch(/^trid: Not included in stock arm64 REMnux \(installed on amd64 only\)\. Use `file` or Detect It Easy instead\.$/);
  });

  it("blames only the command the shell named in a compound command", async () => {
    const deps = createMockDeps();
    target(deps, "arm64", ["nosuchtool"]);
    const env = parseEnvelope(await handleRunTool(deps, { command: "tracesc -h; nosuchtool x" }));
    expect(env.data.output_advisory).toBeUndefined();
  });

  it("reads a missing-command message redirected to stdout when the command failed", async () => {
    const deps = createMockDeps();
    vi.mocked(deps.connector.executeShell).mockImplementation(async (cmd: string) =>
      cmd === ARCH_PROBE ? ok("arm64\n")
        : cmd === "command -v trid" ? { stdout: "", stderr: "", exitCode: 1 }
        : { stdout: "bash: line 1: trid: command not found\n", stderr: "", exitCode: 127 },
    );
    const env = parseEnvelope(await handleRunTool(deps, { command: "trid /home/remnux/files/samples/x.bin 2>&1" }));
    expect(env.data.output_advisory).toMatch(/^trid: Not included in stock arm64 REMnux/);
  });

  it("ignores a forged missing-command line when the named command is present", async () => {
    const deps = createMockDeps();
    target(deps, "arm64", []);
    vi.mocked(deps.connector.executeShell).mockImplementation(async (cmd: string) =>
      cmd === ARCH_PROBE ? ok("arm64\n")
        : cmd === "command -v trid" ? ok("/usr/local/bin/trid\n")
        : { stdout: "", stderr: "bash: line 1: trid: command not found", exitCode: 1 },
    );
    const env = parseEnvelope(await handleRunTool(deps, { command: "strings /home/remnux/files/samples/x.bin | grep -q nothing" }));
    expect(env.data.output_advisory).toBeUndefined();
  });

  it("ignores a missing-command line in the stdout of a command that succeeded, such as a sample's text", async () => {
    const deps = createMockDeps();
    vi.mocked(deps.connector.executeShell).mockImplementation(async (cmd: string) =>
      cmd === ARCH_PROBE ? ok("arm64\n") : ok("bash: line 1: trid: command not found\nError: thug: not found\n"),
    );
    const env = parseEnvelope(await handleRunTool(deps, { command: "cat /home/remnux/files/samples/notes.txt" }));
    expect(env.data.output_advisory).toBeUndefined();
  });

  it("adds nothing on amd64", async () => {
    const deps = createMockDeps();
    target(deps, "amd64", ["trid"]);
    const env = parseEnvelope(await handleRunTool(deps, { command: "trid /home/remnux/files/samples/x.bin" }));
    expect(env.data.output_advisory).toBeUndefined();
  });
});

describe("suggest_tools", () => {
  function fileIs(deps: HandlerDeps, fileOutput: string) {
    vi.mocked(deps.connector.execute).mockResolvedValue(ok(fileOutput));
  }

  it("drops the js_unshroud passage only when the probe finds js_unshroud missing", async () => {
    const amd = createMockDeps();
    target(amd, "amd64", []);
    fileIs(amd, "/samples/page.html: HTML document, ASCII text");
    const present = parseEnvelope(await handleSuggestTools(amd, { file: "page.html" })).data.analysis_hints;
    expect(present).toContain("js_unshroud run --url");

    const arm = createMockDeps();
    target(arm, "arm64", ["js_unshroud"]);
    fileIs(arm, "/samples/page.html: HTML document, ASCII text");
    const absent = parseEnvelope(await handleSuggestTools(arm, { file: "page.html" })).data.analysis_hints;
    expect(absent).not.toContain("js_unshroud run --url");
    expect(absent).toContain("js_unshroud, which records JavaScript behavior on live web pages, is not installed on this REMnux system.");
    // Everything before the passage is unchanged.
    expect(absent.startsWith(present.slice(0, present.indexOf("When the JavaScript lives on a live web page")))).toBe(true);
  });

  it("keeps the js_unshroud passage on an arm64 system where the probe finds it installed", async () => {
    const deps = createMockDeps();
    target(deps, "arm64", []);
    fileIs(deps, "/samples/page.html: HTML document, ASCII text");
    expect(parseEnvelope(await handleSuggestTools(deps, { file: "page.html" })).data.analysis_hints).toContain("js_unshroud run --url");
  });

  it("keeps qltool and drops only tracesc from the shellcode hint when tracesc is missing", async () => {
    const deps = createMockDeps();
    target(deps, "arm64", ["tracesc"]);
    fileIs(deps, "/samples/sc.bin: data");
    const hints = parseEnvelope(await handleSuggestTools(deps, { file: "sc.bin" })).data.analysis_hints;
    expect(hints).toContain("For deep analysis, qltool (Qiling) provides multi-platform emulation. Use strings");
    expect(hints).not.toContain("tracesc");
  });

  it("marks recommended and additional tools that stock arm64 REMnux omits or limits", async () => {
    const deps = createMockDeps();
    target(deps, "arm64", ["tracesc"]);
    fileIs(deps, "/samples/sc.bin: data");
    const data = parseEnvelope(await handleSuggestTools(deps, { file: "sc.bin", depth: "deep" })).data;
    const tracesc = data.recommended_tools.find((t: { name: string }) => t.name === "tracesc");
    expect(tracesc).toMatchObject({ available: false, arch_note: expect.stringMatching(/^Not included in stock arm64 REMnux/) });

    const pe = createMockDeps();
    target(pe, "arm64", []);
    fileIs(pe, "/samples/x.exe: PE32 executable (GUI) Intel 80386, for MS Windows");
    const peData = parseEnvelope(await handleSuggestTools(pe, { file: "x.exe" })).data;
    const bytehist = peData.additional_tools.find((t: { name: string }) => t.name === "Bytehist");
    expect(bytehist.arch_note).toMatch(/^Not included in stock arm64 REMnux/);
    expect(peData.additional_tools_note).toMatch(/Tools with an arch_note are ones that stock REMnux does not include/);

    const pdf = createMockDeps();
    target(pdf, "arm64", []);
    fileIs(pdf, "/samples/d.pdf: PDF document, version 1.7");
    const peepdf = parseEnvelope(await handleSuggestTools(pdf, { file: "d.pdf", depth: "deep" })).data
      .recommended_tools.find((t: { name: string }) => t.name === "peepdf-3");
    expect(peepdf).toBeDefined();
    expect(peepdf.available).toBeUndefined();
    expect(peepdf.arch_note).toBe("On arm64 REMnux: JavaScript emulation is unavailable.");
  });

  it("leaves amd64 output without arch notes and with the original note text", async () => {
    const deps = createMockDeps();
    target(deps, "amd64", []);
    fileIs(deps, "/samples/x.exe: PE32 executable (GUI) Intel 80386, for MS Windows");
    const data = parseEnvelope(await handleSuggestTools(deps, { file: "x.exe", depth: "deep" })).data;
    expect(JSON.stringify(data)).not.toContain("arch_note");
    expect(data.additional_tools_note).toBe(
      "Other tools installed on REMnux for this file type, beyond those analyze_file auto-runs. " +
      "These are discovery pointers (name, purpose, docs link) — not runnable commands. " +
      "To use one, get its exact command from the linked docs, then run_tool it.",
    );
  });

  it("treats a failed availability probe as unknown, not as every tool missing", async () => {
    const deps = createMockDeps();
    target(deps, "arm64", []);
    const base = vi.mocked(deps.connector.executeShell).getMockImplementation()!;
    vi.mocked(deps.connector.executeShell).mockImplementation(async (cmd: string, opts) =>
      cmd.includes("which ") ? { stdout: "", stderr: "", exitCode: 124 } : base(cmd, opts),
    );
    fileIs(deps, "/samples/page.html: HTML document, ASCII text");
    const data = parseEnvelope(await handleSuggestTools(deps, { file: "page.html", depth: "deep" })).data;
    expect(data.analysis_hints).toContain("js_unshroud run --url");
    expect(data.recommended_tools.some((t: { available?: boolean }) => t.available === false)).toBe(false);
  });
});

describe("analyze_file", () => {
  it("explains a deep-tier tool that stock arm64 REMnux omits", async () => {
    const deps = createMockDeps();
    target(deps, "arm64", ["tracesc"]);
    vi.mocked(deps.connector.execute).mockResolvedValue(ok("/samples/sc.bin: data"));
    const env = parseEnvelope(await handleAnalyzeFile(deps, { file: "sc.bin", depth: "deep" }));
    const skipped = env.data.tools_skipped.find((t: { name: string }) => t.name === "tracesc");
    expect(skipped.skip_type).toBe("not_installed");
    expect(skipped.reason).toBe(
      "Tool not installed. tracesc: Not included in stock arm64 REMnux (installed on amd64 only). Use speakeasy or qiling instead.",
    );
  });

  it("blames the command the shell named, not the tool that called it", async () => {
    const deps = createMockDeps();
    target(deps, "arm64", ["wine"]);
    vi.mocked(deps.connector.execute).mockResolvedValue(ok("/samples/sc.bin: data"));
    const base = vi.mocked(deps.connector.executeShell).getMockImplementation()!;
    vi.mocked(deps.connector.executeShell).mockImplementation(async (cmd: string, opts) =>
      /(^|\s)tracesc\s/.test(cmd)
        ? { stdout: "", stderr: "/usr/bin/tracesc: line 3: wine: command not found", exitCode: 127 }
        : base(cmd, opts),
    );
    const env = parseEnvelope(await handleAnalyzeFile(deps, { file: "sc.bin", depth: "deep" }));
    const reason = env.data.tools_skipped.find((t: { name: string }) => t.name === "tracesc").reason;
    expect(reason).toMatch(/^Tool not installed\. wine: Not included in stock arm64 REMnux/);
    expect(reason).not.toMatch(/tracesc:/);
  });

  it("adds no note to a manual-only tool that was installed by hand on arm64", async () => {
    const deps = createMockDeps();
    target(deps, "arm64", []);
    vi.mocked(deps.connector.execute).mockResolvedValue(ok("/samples/page.html: HTML document, ASCII text"));
    const env = parseEnvelope(await handleAnalyzeFile(deps, { file: "page.html", depth: "deep" }));
    expect(env.data.tools_skipped.find((t: { name: string }) => t.name === "js_unshroud").reason).toBe(
      "Requires user-supplied arguments (use run_tool manually)",
    );
  });

  it("qualifies a manual-only tool's skip when stock arm64 REMnux omits it", async () => {
    const deps = createMockDeps();
    target(deps, "arm64", ["js_unshroud"]);
    vi.mocked(deps.connector.execute).mockResolvedValue(ok("/samples/page.html: HTML document, ASCII text"));
    const env = parseEnvelope(await handleAnalyzeFile(deps, { file: "page.html", depth: "deep" }));
    const skipped = env.data.tools_skipped.find((t: { name: string }) => t.name === "js_unshroud");
    expect(skipped.skip_type).toBe("requires_user_args");
    expect(skipped.reason).toMatch(/^Requires user-supplied arguments \(use run_tool manually\)\. Not included in stock arm64 REMnux/);
  });

  it("keeps the existing reasons on amd64", async () => {
    const deps = createMockDeps();
    target(deps, "amd64", ["tracesc"]);
    vi.mocked(deps.connector.execute).mockResolvedValue(ok("/samples/sc.bin: data"));
    const env = parseEnvelope(await handleAnalyzeFile(deps, { file: "sc.bin", depth: "deep" }));
    expect(env.data.tools_skipped.find((t: { name: string }) => t.name === "tracesc").reason).toBe("Tool not installed");
  });
});

describe("download_from_url with thug", () => {
  it("reports a missing thug as missing, with the curl alternative", async () => {
    const deps = createMockDeps();
    target(deps, "arm64", ["thug"]);
    vi.mocked(deps.connector.execute).mockImplementation(async (cmd: string[]) =>
      cmd[0] === "test" ? { stdout: "", stderr: "", exitCode: 1 } : ok(""),
    );
    const env = parseEnvelope(await handleDownloadFromUrl(deps, { url: "https://example.com/x", method: "thug" }));
    expect(env.success).toBe(false);
    expect(env.error_code).toBe("NOT_FOUND");
    expect(env.error).toMatch(/^thug is not installed on this REMnux system\. Not included in stock arm64 REMnux/);
    expect(env.remediation).toMatch(/method 'curl'.*without executing JavaScript/);
    // thug itself never ran.
    const shellCalls = vi.mocked(deps.connector.executeShell).mock.calls.map((c) => c[0]);
    expect(shellCalls.some((c) => c.startsWith("thug "))).toBe(false);
  });

  it("keeps a download thug made even when thug exits non-zero", async () => {
    const deps = createMockDeps();
    vi.mocked(deps.connector.execute).mockImplementation(async (cmd: string[]) => {
      if (cmd[0] === "test") return { stdout: "", stderr: "", exitCode: 1 };
      if (cmd[0] === "file") return ok("PE32 executable");
      if (cmd[0] === "stat") return ok("2048");
      return ok("abc123  file");
    });
    vi.mocked(deps.connector.executeShell).mockImplementation(async (cmd: string) => {
      if (cmd === "command -v thug") return ok("/usr/local/bin/thug\n");
      if (cmd.startsWith("thug ")) return { stdout: "", stderr: "[WARNING] some JS error", exitCode: 1 };
      if (cmd.startsWith("find ")) return ok("/output/thug-1/application/x-dosexec/payload.exe\n");
      return ok("");
    });
    const env = parseEnvelope(await handleDownloadFromUrl(deps, { url: "https://example.com/x", method: "thug" }));
    expect(env.success).toBe(true);
    expect(env.data.thug_exit_code).toBe(1);
  });

  it("still reports a URL that served nothing when thug is present", async () => {
    const deps = createMockDeps();
    target(deps, "amd64", []);
    vi.mocked(deps.connector.execute).mockImplementation(async (cmd: string[]) =>
      cmd[0] === "test" ? { stdout: "", stderr: "", exitCode: 1 } : ok(""),
    );
    vi.mocked(deps.connector.executeShell).mockImplementation(async (cmd: string) => {
      if (cmd === "command -v thug") return ok("/usr/local/bin/thug\n");
      if (cmd.startsWith("thug ")) return { stdout: "", stderr: "[ERROR] connection refused", exitCode: 1 };
      return ok("");
    });
    const env = parseEnvelope(await handleDownloadFromUrl(deps, { url: "https://example.com/x", method: "thug" }));
    expect(env.error_code).toBe("DOWNLOAD_FAILED");
    expect(env.error).toMatch(/^Thug did not download any files/);
  });
});
