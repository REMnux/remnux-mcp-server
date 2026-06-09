import { describe, it, expect, vi } from "vitest";
import { handleRunTool } from "../run-tool.js";
import { createMockDeps, ok, parseEnvelope } from "./helpers.js";

/**
 * Issue #1 (run_tool side) + Issue #2 (%OUTPUT% on the manual path).
 *
 * The contract: the model runs invocations, not names. run_tool only performs
 * the zero-false-positive ".py" rewrite; pseudo-tool aliases pass through and
 * fail naturally rather than being blocked with an advisory.
 */
describe("handleRunTool — name resolution & %OUTPUT%", () => {
  function shellCalls(deps: ReturnType<typeof createMockDeps>) {
    return vi.mocked(deps.connector.executeShell).mock.calls.map((c) => c[0] as string);
  }

  it("rewrites a bare .py registry name to its real command", async () => {
    const deps = createMockDeps({ noSandbox: true });
    vi.mocked(deps.connector.executeShell).mockResolvedValue(ok("out"));
    await handleRunTool(deps, { command: "emldump -s", input_file: "x.eml" });
    expect(shellCalls(deps)[0]).toBe("emldump.py -s '/samples/x.eml'");
  });

  it("rewrites .py names even when the bare token looks like a real command (1768)", async () => {
    const deps = createMockDeps({ noSandbox: true });
    vi.mocked(deps.connector.executeShell).mockResolvedValue(ok("out"));
    await handleRunTool(deps, { command: "1768", input_file: "b.bin" });
    expect(shellCalls(deps)[0]).toBe("1768.py '/samples/b.bin'");
  });

  it("does NOT rewrite a real binary whose command is not name+'.py' (capa)", async () => {
    const deps = createMockDeps({ noSandbox: true });
    vi.mocked(deps.connector.executeShell).mockResolvedValue(ok("out"));
    await handleRunTool(deps, { command: "capa -vv", input_file: "x.exe" });
    expect(shellCalls(deps)[0]).toBe("capa -vv '/samples/x.exe'");
  });

  it("does NOT rewrite a command already given in .py form", async () => {
    const deps = createMockDeps({ noSandbox: true });
    vi.mocked(deps.connector.executeShell).mockResolvedValue(ok("out"));
    await handleRunTool(deps, { command: "pdfid.py", input_file: "a.pdf" });
    expect(shellCalls(deps)[0]).toBe("pdfid.py '/samples/a.pdf'");
  });

  it("passes a pseudo-tool alias through unchanged — no rewrite, no advisory block", async () => {
    const deps = createMockDeps({ noSandbox: true });
    vi.mocked(deps.connector.executeShell).mockResolvedValue(ok("", 127));
    const result = await handleRunTool(deps, { command: "vol3-pslist", input_file: "m.raw" });
    const env = parseEnvelope(result);
    // It runs (and fails naturally at the shell) rather than being blocked.
    expect(shellCalls(deps)[0]).toBe("vol3-pslist '/samples/m.raw'");
    expect(env.data?.command_blocked).toBeUndefined();
  });

  it("resolves the %OUTPUT% sentinel to the session output dir before execution", async () => {
    const deps = createMockDeps({ noSandbox: true, outputDir: "/out" });
    vi.mocked(deps.connector.executeShell).mockResolvedValue(ok("out"));
    await handleRunTool(deps, {
      command: "box-js --output-dir %OUTPUT%/box-js-out",
      input_file: "a.js",
    });
    expect(shellCalls(deps)[0]).toBe(
      "box-js --output-dir /out/box-js-out '/samples/a.js'",
    );
  });

  it("still blocks a catastrophic command after the .py rewrite (blocklist runs on the resolved command)", async () => {
    const deps = createMockDeps({ noSandbox: true });
    vi.mocked(deps.connector.executeShell).mockResolvedValue(ok("out"));
    const result = await handleRunTool(deps, { command: "emldump -s; rm -rf /" });
    const env = parseEnvelope(result);
    expect(env.success).toBe(false);
    expect(env.error_code).toBe("COMMAND_BLOCKED");
    expect(vi.mocked(deps.connector.executeShell)).not.toHaveBeenCalled();
  });

  it("runs the same .py binary whether the model passes the bare or .py form (parser binding invariant)", async () => {
    const deps = createMockDeps({ noSandbox: true });
    vi.mocked(deps.connector.executeShell).mockResolvedValue(ok("<pdfid output>"));
    await handleRunTool(deps, { command: "pdfid", input_file: "a.pdf" });
    await handleRunTool(deps, { command: "pdfid.py", input_file: "a.pdf" });
    const calls = shellCalls(deps);
    // Both resolve to the identical executed command, so detectToolName binds
    // the same parser ("pdfid") in both cases.
    expect(calls[0]).toBe("pdfid.py '/samples/a.pdf'");
    expect(calls[1]).toBe("pdfid.py '/samples/a.pdf'");
  });

  it("does NOT rewrite a %OUTPUT% substring that appears inside the input_file path", async () => {
    const deps = createMockDeps({ noSandbox: true, outputDir: "/out" });
    vi.mocked(deps.connector.executeShell).mockResolvedValue(ok("out"));
    await handleRunTool(deps, { command: "strings", input_file: "%OUTPUT%/weird.bin" });
    // The sentinel in the sample filename must be left intact, not resolved to /out.
    expect(shellCalls(deps)[0]).toBe("strings '/samples/%OUTPUT%/weird.bin'");
  });

  it("rewrites a .py name even with leading whitespace in the command", async () => {
    const deps = createMockDeps({ noSandbox: true });
    vi.mocked(deps.connector.executeShell).mockResolvedValue(ok("out"));
    await handleRunTool(deps, { command: "  emldump -s", input_file: "x.eml" });
    expect(shellCalls(deps)[0]).toBe("emldump.py -s '/samples/x.eml'");
  });
});
