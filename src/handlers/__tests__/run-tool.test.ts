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

  describe("discouraged pattern warnings", () => {
    it("blocks raw yara command with warning", async () => {
      const deps = createMockDeps();

      const result = await handleRunTool(deps, {
        command: "yara /path/to/sample.exe",
      });

      const env = parseEnvelope(result);
      expect(env.success).toBe(true); // Warning is not an error
      expect(env.data.command_blocked).toBe(true);
      expect(env.data.warning).toBe("Raw yara command detected.");
      expect(env.data.suggestion).toContain("yara-forge");
      expect(env.data.suggestion).toContain("yara-rules");
      // Verify command was NOT executed
      expect(deps.connector.executeShell).not.toHaveBeenCalled();
    });

    it("blocks raw yara with full path", async () => {
      const deps = createMockDeps();

      const result = await handleRunTool(deps, {
        command: "/usr/bin/yara sample.exe",
      });

      const env = parseEnvelope(result);
      expect(env.data.command_blocked).toBe(true);
      expect(deps.connector.executeShell).not.toHaveBeenCalled();
    });

    it("allows yara-forge (not discouraged)", async () => {
      const deps = createMockDeps();
      vi.mocked(deps.connector.executeShell).mockResolvedValue(ok("No matches"));

      const result = await handleRunTool(deps, {
        command: "yara-forge sample.exe",
      });

      const env = parseEnvelope(result);
      expect(env.success).toBe(true);
      expect(env.data.command_blocked).toBeUndefined();
      expect(deps.connector.executeShell).toHaveBeenCalled();
    });

    it("allows yara-rules (not discouraged)", async () => {
      const deps = createMockDeps();
      vi.mocked(deps.connector.executeShell).mockResolvedValue(ok("Matches found"));

      const result = await handleRunTool(deps, {
        command: "yara-rules sample.exe",
      });

      const env = parseEnvelope(result);
      expect(env.success).toBe(true);
      expect(env.data.command_blocked).toBeUndefined();
      expect(deps.connector.executeShell).toHaveBeenCalled();
    });

    it("allows raw yara with --acknowledge-raw flag", async () => {
      const deps = createMockDeps();
      vi.mocked(deps.connector.executeShell).mockResolvedValue(ok("Custom rule matched"));

      const result = await handleRunTool(deps, {
        command: "yara --acknowledge-raw /path/to/rules.yar sample.exe",
      });

      const env = parseEnvelope(result);
      expect(env.success).toBe(true);
      expect(env.data.command_blocked).toBeUndefined();
      expect(deps.connector.executeShell).toHaveBeenCalled();
    });

    it("does not allow bypass via filename containing --acknowledge-raw", async () => {
      const deps = createMockDeps();

      const result = await handleRunTool(deps, {
        command: "yara",
        input_file: "--acknowledge-raw/malware.exe",
      });

      const env = parseEnvelope(result);
      // Should still be blocked - the --acknowledge-raw must be in args.command, not in the path
      expect(env.data.command_blocked).toBe(true);
      expect(deps.connector.executeShell).not.toHaveBeenCalled();
    });
  });

  describe("advisory patterns", () => {
    it("returns advisory when using strings command", async () => {
      const deps = createMockDeps({ noSandbox: true });
      vi.mocked(deps.connector.executeShell).mockResolvedValue(ok("output"));

      const result = await handleRunTool(deps, {
        command: "strings -n 8",
        input_file: "sample.bin",
      });

      const env = parseEnvelope(result);
      expect(env.success).toBe(true);
      expect(env.data.advisory).toContain("INCOMPLETE");
      expect(env.data.advisory).toContain("pestr");
      expect(env.data.advisory).toContain("strings -el");
    });

    it("returns advisory for strings with embedded path", async () => {
      const deps = createMockDeps({ noSandbox: true });
      vi.mocked(deps.connector.executeShell).mockResolvedValue(ok("output"));

      const result = await handleRunTool(deps, {
        command: "strings /path/to/sample.exe | grep password",
      });

      const env = parseEnvelope(result);
      expect(env.success).toBe(true);
      expect(env.data.advisory).toContain("pestr");
    });

    it("does not return advisory for pestr command", async () => {
      const deps = createMockDeps({ noSandbox: true });
      vi.mocked(deps.connector.executeShell).mockResolvedValue(ok("output"));

      const result = await handleRunTool(deps, {
        command: "pestr",
        input_file: "sample.exe",
      });

      const env = parseEnvelope(result);
      expect(env.success).toBe(true);
      expect(env.data.advisory).toBeUndefined();
    });
  });
});
