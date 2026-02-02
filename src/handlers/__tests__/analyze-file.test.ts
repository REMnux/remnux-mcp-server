import { describe, it, expect, vi } from "vitest";
import { handleAnalyzeFile } from "../analyze-file.js";
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
});
