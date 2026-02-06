import { describe, it, expect, vi } from "vitest";
import { handleRunTool } from "../run-tool.js";
import { createMockDeps, ok, parseEnvelope } from "./helpers.js";

describe("handleRunTool", () => {
  it("skips path validation when noSandbox is true", async () => {
    const deps = createMockDeps({ noSandbox: true });
    vi.mocked(deps.connector.executeShell).mockResolvedValue(ok("output"));

    // With noSandbox, path validation is skipped entirely
    const result = await handleRunTool(deps, {
      command: "strings",
      input_file: "subdir/sample.exe",
    });

    const env = parseEnvelope(result);
    expect(env.success).toBe(true);
    expect(env.data.command).toBe("strings '/samples/subdir/sample.exe'");
    // Verify no path validation was attempted (connector was called directly)
    expect(deps.connector.executeShell).toHaveBeenCalled();
  });

  it("escapes single quotes in input_file path", async () => {
    const deps = createMockDeps({ noSandbox: true });
    vi.mocked(deps.connector.executeShell).mockResolvedValue(ok("output"));

    await handleRunTool(deps, {
      command: "strings",
      input_file: "file'name.exe",
    });

    const call = vi.mocked(deps.connector.executeShell).mock.calls[0];
    // Single quote should be escaped as '\'' inside the single-quoted path
    expect(call[0]).toBe("strings '/samples/file'\\''name.exe'");
  });

  it("uses args.timeout override when provided", async () => {
    const deps = createMockDeps({ timeout: 300 });
    vi.mocked(deps.connector.executeShell).mockResolvedValue(ok(""));

    // Without input_file, cwd is not set
    await handleRunTool(deps, { command: "strings foo", timeout: 60 });

    const call = vi.mocked(deps.connector.executeShell).mock.calls[0];
    expect(call[1]).toEqual({ timeout: 60000 });
  });

  it("falls back to config.timeout when args.timeout is undefined", async () => {
    const deps = createMockDeps({ timeout: 300 });
    vi.mocked(deps.connector.executeShell).mockResolvedValue(ok(""));

    // Without input_file, cwd is not set
    await handleRunTool(deps, { command: "strings foo" });

    const call = vi.mocked(deps.connector.executeShell).mock.calls[0];
    expect(call[1]).toEqual({ timeout: 300000 });
  });

  it("sets cwd to samplesDir when input_file is provided", async () => {
    const deps = createMockDeps({ timeout: 300 });
    vi.mocked(deps.connector.executeShell).mockResolvedValue(ok(""));

    await handleRunTool(deps, { command: "strings", input_file: "sample.exe" });

    const call = vi.mocked(deps.connector.executeShell).mock.calls[0];
    expect(call[1]).toEqual({ timeout: 300000, cwd: "/samples" });
  });

  it("returns empty stdout without error", async () => {
    const deps = createMockDeps();
    vi.mocked(deps.connector.executeShell).mockResolvedValue(ok(""));

    const result = await handleRunTool(deps, { command: "strings foo" });
    const env = parseEnvelope(result);
    expect(env.success).toBe(true);
    expect(env.data.stdout).toBe("");
  });

  it("rejects blocked commands", async () => {
    const deps = createMockDeps();

    const result = await handleRunTool(deps, { command: "eval malicious" });
    const env = parseEnvelope(result);
    expect(env.success).toBe(false);
    expect(env.error_code).toBe("COMMAND_BLOCKED");
  });

  it("rejects invalid input_file path when sandbox is enabled", async () => {
    const deps = createMockDeps();

    const result = await handleRunTool(deps, {
      command: "strings",
      input_file: "../../../etc/passwd",
    });

    const env = parseEnvelope(result);
    expect(env.success).toBe(false);
    expect(env.error_code).toBe("INVALID_PATH");
  });

  it("wraps connector errors into formatted error response", async () => {
    const deps = createMockDeps();
    vi.mocked(deps.connector.executeShell).mockRejectedValue(new Error("timeout exceeded"));

    const result = await handleRunTool(deps, { command: "strings foo" });
    const env = parseEnvelope(result);
    expect(env.success).toBe(false);
    expect(result.isError).toBe(true);
  });
});
