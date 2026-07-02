import { describe, it, expect, vi } from "vitest";
import { handleAnalyzeFile, generateNextSteps } from "../analyze-file.js";
import { createMockDeps, ok, parseEnvelope } from "./helpers.js";

describe("handleAnalyzeFile", () => {
  it("detects PE file and runs tools", async () => {
    const deps = createMockDeps();
    vi.mocked(deps.connector.execute).mockResolvedValue(
      ok("/samples/test.exe: PE32 executable")
    );
    vi.mocked(deps.connector.executeShell).mockResolvedValue(ok("tool output"));

    const result = await handleAnalyzeFile(deps, { file: "test.exe" });
    const env = parseEnvelope(result);
    expect(env.success).toBe(true);
    expect(env.data.matched_category).toBe("PE");
    expect(env.data.tools_run.length).toBeGreaterThan(0);
  });

  it("surfaces r2ghidra as a skipped (manual) decompile step at deep depth, never auto-run", async () => {
    const deps = createMockDeps();
    vi.mocked(deps.connector.execute).mockResolvedValue(
      ok("/samples/test.exe: PE32 executable")
    );
    vi.mocked(deps.connector.executeShell).mockResolvedValue(ok("tool output"));

    const result = await handleAnalyzeFile(deps, { file: "test.exe", depth: "deep" });
    const env = parseEnvelope(result);
    const skipped = env.data.tools_skipped.find((t: { name: string }) => t.name === "r2ghidra");
    expect(skipped).toBeDefined();
    expect(skipped.skip_type).toBe("requires_user_args");
    expect(skipped.invocation).toContain("pdg @ entry0; pdg @ main");
    expect(env.data.tools_run.map((t: { name: string }) => t.name)).not.toContain("r2ghidra");
  });

  it("skips tools with exit code 127 (not installed)", async () => {
    const deps = createMockDeps();
    vi.mocked(deps.connector.execute).mockResolvedValue(
      ok("/samples/test.exe: PE32 executable")
    );
    vi.mocked(deps.connector.executeShell).mockResolvedValue({
      stdout: "",
      stderr: "peframe: command not found",
      exitCode: 127,
    });

    const result = await handleAnalyzeFile(deps, { file: "test.exe" });
    const env = parseEnvelope(result);
    expect(env.data.tools_skipped).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ reason: "Tool not installed" }),
      ])
    );
  });

  it("maps timeout errors to tools_failed", async () => {
    const deps = createMockDeps();
    vi.mocked(deps.connector.execute).mockResolvedValue(
      ok("/samples/test.exe: PE32 executable")
    );
    vi.mocked(deps.connector.executeShell).mockRejectedValue(
      new Error("Command timeout exceeded")
    );

    const result = await handleAnalyzeFile(deps, { file: "test.exe" });
    const env = parseEnvelope(result);
    expect(env.data.tools_failed).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ error: "Timed out" }),
      ])
    );
  });

  it("returns error when file command produces empty output", async () => {
    const deps = createMockDeps();
    vi.mocked(deps.connector.execute).mockResolvedValue(ok(""));

    const result = await handleAnalyzeFile(deps, { file: "test.exe" });
    const env = parseEnvelope(result);
    expect(env.success).toBe(false);
    expect(env.error_code).toBe("EMPTY_OUTPUT");
  });

  it("includes IOCs in response from tool output", async () => {
    const deps = createMockDeps();
    vi.mocked(deps.connector.execute).mockResolvedValue(
      ok("/samples/test.exe: PE32 executable (console)")
    );
    vi.mocked(deps.connector.executeShell).mockResolvedValue(
      ok("strings output: connects to 45.33.32.156 on port 4444")
    );

    const result = await handleAnalyzeFile(deps, { file: "test.exe" });
    const env = parseEnvelope(result);
    expect(env.success).toBe(true);
    expect(env.data.iocs).toBeDefined();
    expect(env.data.iocs.some((i: { type: string; value: string }) => i.type === "ipv4" && i.value === "45.33.32.156")).toBe(true);
  });

  it("extracts IOCs past a tool's display budget (full output feeds extraction)", async () => {
    const deps = createMockDeps();
    // JavaScript file → chain runs js-beautify/webcrack/box-js, all with <=20KB
    // display budgets. Put a C2 URL well past those budgets, mirroring webcrack
    // recovering a downloadUrl deep in its deobfuscated output.
    vi.mocked(deps.connector.execute).mockResolvedValue(
      ok("/samples/dropper.js: JavaScript source, ASCII text")
    );
    const deepUrl = "A".repeat(30000) +
      ' downloadUrl: "http://evilc2downloader.com/stage2.ps1" ' +
      "B".repeat(3000);
    vi.mocked(deps.connector.executeShell).mockResolvedValue(ok(deepUrl));

    const result = await handleAnalyzeFile(deps, { file: "dropper.js", depth: "standard" });
    const env = parseEnvelope(result);
    expect(env.success).toBe(true);
    // The URL sits past every JS tool's display budget; it must still be
    // extracted because IOC extraction runs on full, not truncated, output.
    expect(
      env.data.iocs.some((i: { value: string }) => i.value.includes("evilc2downloader.com"))
    ).toBe(true);
  });

  it("records non-zero exit with valid stdout in tools_run", async () => {
    const deps = createMockDeps();
    vi.mocked(deps.connector.execute).mockResolvedValue(
      ok("/samples/test.exe: PE32 executable")
    );
    vi.mocked(deps.connector.executeShell).mockResolvedValue({
      stdout: "partial output here",
      stderr: "some warning",
      exitCode: 2,
    });

    const result = await handleAnalyzeFile(deps, { file: "test.exe" });
    const env = parseEnvelope(result);
    expect(env.data.tools_run.length).toBeGreaterThan(0);
  });

  it("records non-timeout errors with original message", async () => {
    const deps = createMockDeps();
    vi.mocked(deps.connector.execute).mockResolvedValue(
      ok("/samples/test.exe: PE32 executable")
    );
    vi.mocked(deps.connector.executeShell).mockRejectedValue(
      new Error("connection refused")
    );

    const result = await handleAnalyzeFile(deps, { file: "test.exe" });
    const env = parseEnvelope(result);
    expect(env.data.tools_failed[0].error).toBe("connection refused");
  });

  it("respects depth parameter for tool filtering", async () => {
    const deps = createMockDeps();
    vi.mocked(deps.connector.execute).mockResolvedValue(
      ok("/samples/test.exe: PE32 executable")
    );
    vi.mocked(deps.connector.executeShell).mockResolvedValue(ok("output"));

    const quickResult = await handleAnalyzeFile(deps, { file: "test.exe", depth: "quick" });
    const standardResult = await handleAnalyzeFile(deps, { file: "test.exe", depth: "standard" });
    const quickEnv = parseEnvelope(quickResult);
    const standardEnv = parseEnvelope(standardResult);

    // Quick should have fewer tools than standard
    const quickTotal = quickEnv.data.tools_run.length + quickEnv.data.tools_skipped.length + quickEnv.data.tools_failed.length;
    const standardTotal = standardEnv.data.tools_run.length + standardEnv.data.tools_skipped.length + standardEnv.data.tools_failed.length;
    expect(quickTotal).toBeLessThan(standardTotal);
  });

  it("returns FILE_NOT_FOUND when file does not exist", async () => {
    const deps = createMockDeps();
    vi.mocked(deps.connector.execute).mockResolvedValueOnce(
      { stdout: "", stderr: "", exitCode: 1 } // test -f fails
    );

    const result = await handleAnalyzeFile(deps, { file: "nonexistent.exe" });
    const env = parseEnvelope(result);
    expect(env.success).toBe(false);
    expect(env.error_code).toBe("FILE_NOT_FOUND");
  });

  it("strips duplicate samples/ prefix from file parameter", async () => {
    const deps = createMockDeps();
    const exec = vi.mocked(deps.connector.execute);
    exec.mockResolvedValue(ok("/samples/test.exe: PE32 executable"));
    vi.mocked(deps.connector.executeShell).mockResolvedValue(ok("tool output"));

    await handleAnalyzeFile(deps, { file: "samples/test.exe" });

    // The test -f call should use /samples/test.exe, not /samples/samples/test.exe
    expect(exec).toHaveBeenCalledWith(
      ["test", "-f", "/samples/test.exe"],
      { timeout: 5000 },
    );
  });
});

describe("generateNextSteps report pointer", () => {
  const POINTER = "Draft a report:";

  it("omits the pointer when there are no substantive results", () => {
    const steps = generateNextSteps("PE", "standard", [], [], 0);
    expect(steps.some((s) => s.startsWith(POINTER))).toBe(false);
    expect(steps.length).toBeLessThanOrEqual(5);
  });

  it("includes the pointer when IOCs were found", () => {
    const steps = generateNextSteps("PE", "standard", [], [], 1);
    expect(steps.some((s) => s.startsWith(POINTER))).toBe(true);
  });

  it("keeps the pointer even when base steps are at the cap (regression for truncation bug)", () => {
    // PE + standard depth + no capa findings (packed) + a not-installed tool + IOCs
    // yields 6 base steps; the pointer must still survive as the final item.
    const toolsSkipped = [
      { name: "peframe", skip_type: "not_installed", reason: "Tool not installed" },
    ] as unknown as Parameters<typeof generateNextSteps>[3];
    const steps = generateNextSteps("PE", "standard", [], toolsSkipped, 1);
    expect(steps.some((s) => s.startsWith(POINTER))).toBe(true);
    expect(steps[steps.length - 1].startsWith(POINTER)).toBe(true);
  });
});
