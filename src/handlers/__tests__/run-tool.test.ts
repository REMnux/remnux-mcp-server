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

  it("rejects blocked commands (null byte injection)", async () => {
    const deps = createMockDeps();

    const result = await handleRunTool(deps, { command: "cat file\x00.txt" });
    const env = parseEnvelope(result);
    expect(env.success).toBe(false);
    expect(env.error_code).toBe("COMMAND_BLOCKED");
  });

  it("allows shell expansion (container isolation)", async () => {
    const deps = createMockDeps();
    vi.mocked(deps.connector.executeShell).mockResolvedValue(ok("root"));

    const result = await handleRunTool(deps, { command: "echo $(whoami)" });
    const env = parseEnvelope(result);
    expect(env.success).toBe(true);
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

    it("returns output_advisory when js_unshroud browser fails to launch (exit 0)", async () => {
      const deps = createMockDeps({ noSandbox: true });
      vi.mocked(deps.connector.executeShell).mockResolvedValue({
        stdout: "",
        stderr:
          "Error during monitoring: ...\nerror: launch: Target page, context or browser has been closed",
        exitCode: 0,
      });

      const result = await handleRunTool(deps, {
        command: "js_unshroud run --url https://example.com --out /tmp/e.jsonl",
      });

      const env = parseEnvelope(result);
      expect(env.success).toBe(true);
      expect(env.data.exit_code).toBe(0);
      expect(env.data.output_advisory).toContain("POSSIBLE CAPTURE FAILURE");
      expect(env.data.output_advisory).toContain("xvfb-run");
    });

    it("returns output_advisory when only 'Error during monitoring' appears", async () => {
      const deps = createMockDeps({ noSandbox: true });
      vi.mocked(deps.connector.executeShell).mockResolvedValue({
        stdout: "Error during monitoring: something failed",
        stderr: "",
        exitCode: 0,
      });

      const result = await handleRunTool(deps, {
        command: "xvfb-run -a js_unshroud run --url https://example.com --out e.jsonl",
      });

      const env = parseEnvelope(result);
      expect(env.data.output_advisory).toContain("POSSIBLE CAPTURE FAILURE");
    });

    it("returns output_advisory for the raw binary path invocation", async () => {
      const deps = createMockDeps({ noSandbox: true });
      vi.mocked(deps.connector.executeShell).mockResolvedValue({
        stdout: "",
        stderr: "browserType.launch: Failed to launch chromium",
        exitCode: 0,
      });

      const result = await handleRunTool(deps, {
        command:
          "/opt/js_unshroud/js_unshroud-linux-x64 run --url https://example.com --out e.jsonl",
      });

      const env = parseEnvelope(result);
      expect(env.data.output_advisory).toContain("POSSIBLE CAPTURE FAILURE");
    });

    it("scans pre-truncation output for the failure signal", async () => {
      const deps = createMockDeps({ noSandbox: true });
      // Failure text sits past the 100KB stdout response budget
      const bigStdout = "x".repeat(101 * 1024) + "\nError during monitoring: launch failed";
      vi.mocked(deps.connector.executeShell).mockResolvedValue({
        stdout: bigStdout,
        stderr: "",
        exitCode: 0,
      });

      const result = await handleRunTool(deps, {
        command: "js_unshroud run --url https://example.com --out e.jsonl",
      });

      const env = parseEnvelope(result);
      expect(env.data.truncated).toBe(true);
      expect(env.data.stdout).not.toContain("Error during monitoring");
      expect(env.data.output_advisory).toContain("POSSIBLE CAPTURE FAILURE");
    });

    it("does not fire when js_unshroud is mentioned but not invoked", async () => {
      const deps = createMockDeps({ noSandbox: true });
      // grep over saved logs that themselves contain a failure trace
      vi.mocked(deps.connector.executeShell).mockResolvedValue(
        ok("saved.log:error: launch: Target page, context or browser has been closed"),
      );

      const result = await handleRunTool(deps, {
        command: "grep -r js_unshroud /home/remnux/files/output/",
      });

      const env = parseEnvelope(result);
      expect(env.data.output_advisory).toBeUndefined();
    });

    it("does not fire for display-free subcommands (analyze/query/correlate)", async () => {
      const deps = createMockDeps({ noSandbox: true });
      vi.mocked(deps.connector.executeShell).mockResolvedValue({
        stdout: "",
        stderr: "Error during monitoring: quoted in analyzed events",
        exitCode: 0,
      });

      const result = await handleRunTool(deps, {
        command: "js_unshroud analyze --input /tmp/e.jsonl --format stats",
      });

      const env = parseEnvelope(result);
      expect(env.data.output_advisory).toBeUndefined();
    });

    it("fires on a nonzero exit code too", async () => {
      const deps = createMockDeps({ noSandbox: true });
      vi.mocked(deps.connector.executeShell).mockResolvedValue({
        stdout: "",
        stderr: "browserType.launch: Failed to launch browser",
        exitCode: 1,
      });

      const result = await handleRunTool(deps, {
        command: "js_unshroud run --url https://example.com --out e.jsonl",
      });

      const env = parseEnvelope(result);
      expect(env.data.output_advisory).toContain("POSSIBLE CAPTURE FAILURE");
    });

    it("does not return output_advisory for a healthy js_unshroud run", async () => {
      const deps = createMockDeps({ noSandbox: true });
      vi.mocked(deps.connector.executeShell).mockResolvedValue(ok("capture complete"));

      const result = await handleRunTool(deps, {
        command: "js_unshroud run --url https://example.com --out /tmp/e.jsonl",
      });

      const env = parseEnvelope(result);
      expect(env.success).toBe(true);
      expect(env.data.output_advisory).toBeUndefined();
    });

    it("does not return output_advisory when another tool emits the same text", async () => {
      const deps = createMockDeps({ noSandbox: true });
      vi.mocked(deps.connector.executeShell).mockResolvedValue(
        ok("log line: browser has been closed"),
      );

      const result = await handleRunTool(deps, {
        command: "grep -r closed logs/",
      });

      const env = parseEnvelope(result);
      expect(env.data.output_advisory).toBeUndefined();
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

    it("does not return advisory when strings already uses -el (Unicode)", async () => {
      const deps = createMockDeps({ noSandbox: true });
      vi.mocked(deps.connector.executeShell).mockResolvedValue(ok("output"));

      const result = await handleRunTool(deps, {
        command: "strings -el",
        input_file: "sample.bin",
      });

      const env = parseEnvelope(result);
      expect(env.success).toBe(true);
      expect(env.data.advisory).toBeUndefined();
    });

    it("does not return advisory for strings -eb (big-endian Unicode)", async () => {
      const deps = createMockDeps({ noSandbox: true });
      vi.mocked(deps.connector.executeShell).mockResolvedValue(ok("output"));

      const result = await handleRunTool(deps, {
        command: "strings -eb sample.bin",
      });

      const env = parseEnvelope(result);
      expect(env.success).toBe(true);
      expect(env.data.advisory).toBeUndefined();
    });
  });
});
