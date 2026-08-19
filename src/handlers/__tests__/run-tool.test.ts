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

/**
 * Oversized-output contract: the server truncates large stdout/stderr with a
 * per-stream notice that names the omitted line range and a recoverable
 * %OUTPUT% recipe, and it warns (non-blocking) when the agent's own pipeline
 * ends in head/tail, because that stage discards output the server would
 * otherwise have returned whole. Background: an agent ran
 * `pestr sprd.exe 2>/dev/null | head -200` on ~1,800 lines and lost the C2
 * URLs at lines 1363-1365 with exit 0 and no signal of any kind.
 */
describe("oversized-output contract", () => {
  // 100 KiB stdout cap, 50 KiB stderr cap (run-tool.ts)
  const STDOUT_CAP = 100 * 1024;
  const STDERR_CAP = 50 * 1024;
  const lines = (n: number) => Array.from({ length: n }, (_, i) => `line ${i + 1}`).join("\n") + "\n";

  describe("limiter advisory (terminal head/tail)", () => {
    it("fires PARTIAL for the incident command, under the cap, with truncated false and no notice", async () => {
      const deps = createMockDeps({ noSandbox: true });
      vi.mocked(deps.connector.executeShell).mockResolvedValue(ok(lines(200)));

      const result = await handleRunTool(deps, {
        command: "pestr sprd.exe 2>/dev/null | head -200",
      });

      const env = parseEnvelope(result);
      expect(env.success).toBe(true);
      expect(env.data.truncated).toBe(false);
      expect(env.data.truncation_notice).toBeUndefined();
      expect(env.data.advisory).toContain("PARTIAL");
      expect(env.data.advisory).toContain("head -200");
      expect(env.data.advisory).toContain("leading");
      // stdout is the exact, unmodified slice: nothing appended into it
      expect(env.data.stdout).toBe(lines(200));
    });

    it("fires for a terminal tail -n stage with 'trailing' wording", async () => {
      const deps = createMockDeps({ noSandbox: true });
      vi.mocked(deps.connector.executeShell).mockResolvedValue(ok("x"));

      const result = await handleRunTool(deps, { command: "strings -el a.bin | tail -n 50" });
      const env = parseEnvelope(result);
      expect(env.data.advisory).toContain("PARTIAL");
      expect(env.data.advisory).toContain("tail -n 50");
      expect(env.data.advisory).toContain("trailing");
    });

    it("fires for head -c (byte prefix) and a full-path head", async () => {
      const deps = createMockDeps({ noSandbox: true });
      vi.mocked(deps.connector.executeShell).mockResolvedValue(ok("x"));

      const a = parseEnvelope(await handleRunTool(deps, { command: "cat a.txt | head -c 5000" }));
      expect(a.data.advisory).toContain("PARTIAL");
      const b = parseEnvelope(await handleRunTool(deps, { command: "cat a.txt | /usr/bin/head" }));
      expect(b.data.advisory).toContain("PARTIAL");
      const c = parseEnvelope(await handleRunTool(deps, { command: "pestr a.exe |& head -50" }));
      expect(c.data.advisory).toContain("PARTIAL");
    });

    it("does not fire for tail -f / -F / --follow (streaming, not limiting)", async () => {
      const deps = createMockDeps({ noSandbox: true });
      vi.mocked(deps.connector.executeShell).mockResolvedValue(ok("x"));

      for (const cmd of ["cat log | tail -f", "cat log | tail -F", "cat log | tail --follow", "cat log | tail -fn 20"]) {
        const env = parseEnvelope(await handleRunTool(deps, { command: cmd }));
        expect(env.data.advisory, cmd).toBeUndefined();
      }
    });

    it("fires for an upstream head stage too: it caps the producer before any later filter", async () => {
      const deps = createMockDeps({ noSandbox: true });
      vi.mocked(deps.connector.executeShell).mockResolvedValue(ok("x"));
      const env = parseEnvelope(
        await handleRunTool(deps, { command: "pestr a.exe | head -500 | grep -i http" }),
      );
      expect(env.data.advisory).toContain("PARTIAL");
      expect(env.data.advisory).toContain("head -500");
    });

    it("does not fire for head/tail outside a pipeline, for range reads, or for content filters", async () => {
      const deps = createMockDeps({ noSandbox: true });
      vi.mocked(deps.connector.executeShell).mockResolvedValue(ok("x"));

      for (const cmd of [
        "tail -n 200 %OUTPUT%/saved.txt",                // paging a saved file, no pipe
        "head -c 4096 sample.bin | xxd",                 // head reads a file; the pipe is after it
        "sed -n '5571,7137p' %OUTPUT%/saved.txt",        // range read, not head/tail
        "pestr a.exe | grep -i 'http' ",                 // content filter only
        "seq 100 | tail -n +1",                          // +1 returns every line
        "pestr a.exe | grep x # | head -5",              // head is inside a comment
      ]) {
        const env = parseEnvelope(await handleRunTool(deps, { command: cmd }));
        expect(env.data.advisory, cmd).toBeUndefined();
      }
    });

    it("does not fire on a quoted '| head' inside an argument", async () => {
      const deps = createMockDeps({ noSandbox: true });
      vi.mocked(deps.connector.executeShell).mockResolvedValue(ok("x"));

      const env = parseEnvelope(
        await handleRunTool(deps, { command: "grep -F '| head -5' notes.txt" }),
      );
      expect(env.data.advisory).toBeUndefined();
      const env2 = parseEnvelope(
        await handleRunTool(deps, { command: 'grep -F "a | head" notes.txt' }),
      );
      expect(env2.data.advisory).toBeUndefined();
    });

    it("joins the strings INCOMPLETE advisory and the PARTIAL advisory when both apply", async () => {
      const deps = createMockDeps({ noSandbox: true });
      vi.mocked(deps.connector.executeShell).mockResolvedValue(ok("x"));

      const env = parseEnvelope(await handleRunTool(deps, { command: "strings a.bin | head -100" }));
      expect(env.data.advisory).toContain("INCOMPLETE");
      expect(env.data.advisory).toContain("PARTIAL");
      expect(env.data.advisory.indexOf("INCOMPLETE")).toBeLessThan(env.data.advisory.indexOf("PARTIAL"));
    });

    it("appends input_file after the whole pipeline (documented hazard: it reaches the last stage)", async () => {
      const deps = createMockDeps({ noSandbox: true });
      vi.mocked(deps.connector.executeShell).mockResolvedValue(ok("x"));

      await handleRunTool(deps, { command: "pestr | head -200", input_file: "sample.exe" });
      const call = vi.mocked(deps.connector.executeShell).mock.calls[0];
      expect(call[0]).toBe("pestr | head -200 '/samples/sample.exe'");
    });
  });

  describe("spill-to-file on stdout truncation", () => {
    const bigOut = () => "o".repeat(31) + "\n";
    it("saves captured stdout under a hash name, reports stdout_saved_file, and points the recipe at the file", async () => {
      const deps = createMockDeps({ noSandbox: true, outputDir: "/output" });
      const big = bigOut().repeat(4000); // 128,000 chars, 4000 lines
      vi.mocked(deps.connector.executeShell).mockResolvedValue(ok(big));
      const env = parseEnvelope(await handleRunTool(deps, { command: "pestr", input_file: "sample.exe" }));
      expect(env.data.stdout_truncated).toBe(true);
      expect(env.data.stdout_saved_file).toMatch(/^run_tool-pestr-[0-9a-f]{12}\.stdout\.txt$/);
      expect(deps.connector.writeFile).toHaveBeenCalledWith(`/output/${env.data.stdout_saved_file}`, Buffer.from(big, "utf-8"));
      const notice: string = env.data.truncation_notice;
      expect(notice).toContain(`'%OUTPUT%/${env.data.stdout_saved_file}'`);
      expect(notice).toMatch(/sed -n '3201,\$p'/);          // 102400 / 32 = 3200 complete lines returned
      expect(notice).toContain("saved");
      expect(notice).not.toMatch(/re-run/i);                  // no need to re-run: the file exists
      expect(notice).not.toMatch(/\bfull output\b/i);
    });

    it("uses the same file name for the same command (idempotent re-runs overwrite)", async () => {
      const deps = createMockDeps({ noSandbox: true, outputDir: "/output" });
      vi.mocked(deps.connector.executeShell).mockResolvedValue(ok(bigOut().repeat(4000)));
      const a = parseEnvelope(await handleRunTool(deps, { command: "pestr", input_file: "sample.exe" }));
      const b = parseEnvelope(await handleRunTool(deps, { command: "pestr", input_file: "sample.exe" }));
      const c = parseEnvelope(await handleRunTool(deps, { command: "pestr", input_file: "other.exe" }));
      expect(a.data.stdout_saved_file).toBe(b.data.stdout_saved_file);
      expect(c.data.stdout_saved_file).not.toBe(a.data.stdout_saved_file);
    });

    it("falls back to the re-run recipe when the write fails", async () => {
      const deps = createMockDeps({ noSandbox: true, outputDir: "/output" });
      vi.mocked(deps.connector.executeShell).mockResolvedValue(ok(bigOut().repeat(4000)));
      vi.mocked(deps.connector.writeFile).mockRejectedValue(new Error("EACCES"));
      const env = parseEnvelope(await handleRunTool(deps, { command: "pestr", input_file: "sample.exe" }));
      expect(env.data.truncated).toBe(true);
      expect(env.data.stdout_saved_file).toBeUndefined();
      expect(env.data.truncation_notice).toMatch(/re-run/i);
      expect(env.data.truncation_notice).toMatch(/sed -n '3201,\$p'/);
    });

    it("does not spill captured stdout over 500 KiB (re-run recipe instead)", async () => {
      const deps = createMockDeps({ noSandbox: true, outputDir: "/output" });
      vi.mocked(deps.connector.executeShell).mockResolvedValue(ok(bigOut().repeat(20000))); // 640,000 chars
      const env = parseEnvelope(await handleRunTool(deps, { command: "pestr", input_file: "sample.exe" }));
      expect(deps.connector.writeFile).not.toHaveBeenCalled();
      expect(env.data.stdout_saved_file).toBeUndefined();
      expect(env.data.truncation_notice).toMatch(/re-run/i);
    });

    it("does not spill when no output directory is configured", async () => {
      const deps = createMockDeps({ noSandbox: true, outputDir: "" });
      vi.mocked(deps.connector.executeShell).mockResolvedValue(ok(bigOut().repeat(4000)));
      const env = parseEnvelope(await handleRunTool(deps, { command: "pestr", input_file: "sample.exe" }));
      expect(deps.connector.writeFile).not.toHaveBeenCalled();
      expect(env.data.stdout_saved_file).toBeUndefined();
      expect(env.data.truncation_notice).not.toContain("%OUTPUT%");
    });

    it("does not spill on stderr-only overflow", async () => {
      const deps = createMockDeps({ noSandbox: true, outputDir: "/output" });
      vi.mocked(deps.connector.executeShell).mockResolvedValue({ stdout: "ok", stderr: "e".repeat(STDERR_CAP + 1), exitCode: 0 });
      const env = parseEnvelope(await handleRunTool(deps, { command: "tool sample.exe" }));
      expect(deps.connector.writeFile).not.toHaveBeenCalled();
      expect(env.data.stdout_saved_file).toBeUndefined();
    });
  });

  describe("per-stream truncation notice and fields", () => {
    it("stdout overflow: per-stream fields, line numbers, %OUTPUT% recipe, never head", async () => {
      const deps = createMockDeps({ noSandbox: true, outputDir: "/output" });
      // 8,000 lines of 16 chars = 128,000 chars > 100 KiB cap
      const big = Array.from({ length: 8000 }, (_, i) => `L${String(i + 1).padStart(14, "0")}`).join("\n") + "\n";
      vi.mocked(deps.connector.executeShell).mockResolvedValue(ok(big));

      const env = parseEnvelope(await handleRunTool(deps, { command: "pestr sample.exe" }));
      expect(env.data.truncated).toBe(true);
      expect(env.data.stdout_truncated).toBe(true);
      expect(env.data.stderr_truncated).toBe(false);
      expect(env.data.full_stdout_length).toBe(big.length);           // legacy alias, verbatim
      expect(env.data.stdout_captured_length).toBe(big.length);
      expect(env.data.stdout_captured_lines).toBe(8000);
      // 16 chars per line incl. newline: 102400 / 16 = 6400 complete lines returned
      expect(env.data.stdout_returned_lines).toBe(6400);
      expect(env.data.stdout).toBe(big.slice(0, STDOUT_CAP));          // exact slice, nothing appended
      const notice: string = env.data.truncation_notice;
      expect(notice).toContain("8000 lines captured");
      expect(notice).toContain("6401");                                // omitted range starts after the last complete line
      // open-ended range: connector trimming or the 10 MiB connector cap can never make it miss the tail
      expect(notice).toMatch(/sed -n '6401,\$p' '%OUTPUT%\/run_tool-[A-Za-z0-9._-]+\.stdout\.txt'/);
      expect(notice).not.toMatch(/sed -n '6401,8000p'/);
      expect(notice).not.toContain("head -N");
      expect(notice).not.toMatch(/\bfull output\b/i);
      expect(notice).toContain("head");                               // it says why head does not help
    });

    it("stderr-only overflow: truncated true, stderr notice, stdout_truncated false, no stdout recipe", async () => {
      const deps = createMockDeps({ noSandbox: true, outputDir: "/output" });
      vi.mocked(deps.connector.executeShell).mockResolvedValue({
        stdout: "ok",
        stderr: "e".repeat(STDERR_CAP + 10),
        exitCode: 0,
      });

      const env = parseEnvelope(await handleRunTool(deps, { command: "tool sample.exe" }));
      expect(env.data.truncated).toBe(true);
      expect(env.data.stdout_truncated).toBe(false);
      expect(env.data.stderr_truncated).toBe(true);
      expect(env.data.stderr_captured_length).toBe(STDERR_CAP + 10);
      expect(env.data.stdout_captured_lines).toBeUndefined();
      expect(env.data.stderr.length).toBe(STDERR_CAP);
      expect(env.data.truncation_notice).toContain("stderr");
      expect(env.data.truncation_notice).toContain("2>");
      expect(env.data.truncation_notice).toContain("( <command> )");   // a bare 2> only covers the last stage of a pipeline
      expect(env.data.truncation_notice).toContain("stdout is complete");
      expect(env.data.truncation_notice).not.toContain("head -N");
    });

    it("both streams overflow: both notices present", async () => {
      const deps = createMockDeps({ noSandbox: true, outputDir: "/output" });
      vi.mocked(deps.connector.executeShell).mockResolvedValue({
        stdout: "o\n".repeat(STDOUT_CAP),
        stderr: "e".repeat(STDERR_CAP + 1),
        exitCode: 0,
      });
      const env = parseEnvelope(await handleRunTool(deps, { command: "tool sample.exe" }));
      expect(env.data.stdout_truncated).toBe(true);
      expect(env.data.stderr_truncated).toBe(true);
      expect(env.data.truncation_notice).toContain("stdout:");
      expect(env.data.truncation_notice).toContain("stderr:");
      expect(env.data.truncation_notice).not.toContain("stdout is complete");
    });

    it("omits the %OUTPUT% recipe when no output directory is configured", async () => {
      const deps = createMockDeps({ noSandbox: true, outputDir: "" });
      vi.mocked(deps.connector.executeShell).mockResolvedValue(ok("o\n".repeat(STDOUT_CAP)));
      const env = parseEnvelope(await handleRunTool(deps, { command: "tool sample.exe" }));
      expect(env.data.truncated).toBe(true);
      expect(env.data.truncation_notice).not.toContain("%OUTPUT%");
      expect(env.data.truncation_notice).toContain("sed -n");          // the one-call re-run recipe still works
    });

    it("a single line longer than the cap gets a byte-slicing recipe, not a line range", async () => {
      const deps = createMockDeps({ noSandbox: true, outputDir: "/output" });
      vi.mocked(deps.connector.executeShell).mockResolvedValue(ok("x".repeat(STDOUT_CAP + 100)));
      const env = parseEnvelope(await handleRunTool(deps, { command: "tool sample.exe" }));
      expect(env.data.stdout_truncated).toBe(true);
      expect(env.data.stdout_captured_lines).toBe(1);
      expect(env.data.stdout_returned_lines).toBe(0);
      expect(env.data.truncation_notice).not.toMatch(/sed -n '1,1p'/);
      expect(env.data.truncation_notice).toMatch(/fold -w/);
      expect(env.data.truncation_notice).not.toMatch(/cut -c/);   // cut -c slices per line, not the stream
      expect(env.data.truncation_notice).toContain("102,400");
    });

    it("does not emit the new fields when nothing was truncated", async () => {
      const deps = createMockDeps({ noSandbox: true });
      vi.mocked(deps.connector.executeShell).mockResolvedValue(ok("small"));
      const env = parseEnvelope(await handleRunTool(deps, { command: "tool sample.exe" }));
      expect(env.data.truncated).toBe(false);
      expect(env.data.stdout_truncated).toBeUndefined();
      expect(env.data.stdout_captured_length).toBeUndefined();
      expect(env.data.findings_scope).toBeUndefined();
    });

    it("parses findings from the captured stdout, past the returned prefix (findings_scope captured_stdout)", async () => {
      const deps = createMockDeps({ noSandbox: true, outputDir: "/output" });
      // yara-rules has a parser; a match line AFTER the 100 KiB cap must still be found
      const body = "x".repeat(STDOUT_CAP + 5) + "\nrule_late /samples/sample.exe\n";
      vi.mocked(deps.connector.executeShell).mockResolvedValue(ok(body));
      const env = parseEnvelope(await handleRunTool(deps, { command: "yara-rules sample.exe" }));
      expect(env.data.truncated).toBe(true);
      expect(JSON.stringify(env.data.findings)).toContain("rule_late");
      expect(env.data.findings_scope).toBe("captured_stdout");
    });

    it("bounds parsing at 512 KiB of captured stdout (findings_scope captured_prefix)", async () => {
      const deps = createMockDeps({ noSandbox: true, outputDir: "/output" });
      const body = "rule_early /samples/sample.exe\n" + "x".repeat(600 * 1024) + "\nrule_late /samples/sample.exe\n";
      vi.mocked(deps.connector.executeShell).mockResolvedValue(ok(body));
      const env = parseEnvelope(await handleRunTool(deps, { command: "yara-rules sample.exe" }));
      expect(JSON.stringify(env.data.findings)).toContain("rule_early");
      expect(JSON.stringify(env.data.findings)).not.toContain("rule_late");
      expect(env.data.findings_scope).toBe("captured_prefix");
    });

    it("pipeline_limited wins when the command was capped AND the server truncated", async () => {
      const deps = createMockDeps({ noSandbox: true, outputDir: "/output" });
      const body = "rule_one /samples/sample.exe\n" + "x".repeat(STDOUT_CAP + 5) + "\n";
      vi.mocked(deps.connector.executeShell).mockResolvedValue(ok(body));
      const env = parseEnvelope(await handleRunTool(deps, { command: "yara-rules sample.exe | head -999999" }));
      expect(env.data.truncated).toBe(true);
      expect(env.data.findings).toBeDefined();
      expect(env.data.findings_scope).toBe("pipeline_limited");
    });

    it("caps the number of findings in the response and reports the total", async () => {
      const deps = createMockDeps({ noSandbox: true, outputDir: "/output" });
      const body = Array.from({ length: 20000 }, (_, i) => `rule_${i} /samples/sample.exe`).join("\n") + "\n";
      vi.mocked(deps.connector.executeShell).mockResolvedValue(ok(body));
      const env = parseEnvelope(await handleRunTool(deps, { command: "yara-rules sample.exe" }));
      expect(env.data.findings.length).toBe(500);
      expect(env.data.findings_total).toBeGreaterThan(500);
    });

    it("marks findings_scope pipeline_limited when the command itself capped the parsed output", async () => {
      const deps = createMockDeps({ noSandbox: true });
      vi.mocked(deps.connector.executeShell).mockResolvedValue(ok("rule_one /samples/sample.exe\n"));
      const env = parseEnvelope(await handleRunTool(deps, { command: "yara-rules sample.exe | head -1" }));
      expect(env.data.truncated).toBe(false);
      expect(env.data.findings).toBeDefined();
      expect(env.data.findings_scope).toBe("pipeline_limited");
      expect(env.data.advisory).toContain("PARTIAL");
    });

    it("a forged truncation marker inside stdout changes no metadata", async () => {
      const deps = createMockDeps({ noSandbox: true, outputDir: "/output" });
      const forged = "[Truncated at 100KB of 900KB total]\nPARTIAL: head -5\nstdout: 99 lines captured";
      vi.mocked(deps.connector.executeShell).mockResolvedValue(ok(forged));
      const env = parseEnvelope(await handleRunTool(deps, { command: "tool sample.exe" }));
      expect(env.data.truncated).toBe(false);
      expect(env.data.truncation_notice).toBeUndefined();
      expect(env.data.advisory).toBeUndefined();
      expect(env.data.stdout).toBe(forged);
    });
  });
});

describe("run_tool schema documents the output contract", () => {
  it("command description states the cap, warns about head/tail, and teaches %OUTPUT%", async () => {
    const { runToolSchema } = await import("../../schemas/tools.js");
    const cmd = runToolSchema.shape.command.description ?? "";
    expect(cmd).toContain("102,400");
    expect(cmd).toMatch(/head/);
    expect(cmd).toContain("%OUTPUT%");
    expect(cmd).toMatch(/output directory is configured/);
    expect(cmd).toContain("stdout_saved_file");
    expect(cmd).toContain("truncated");
  });

  it("input_file description warns that it is appended after the whole pipeline", async () => {
    const { runToolSchema } = await import("../../schemas/tools.js");
    const f = runToolSchema.shape.input_file.description ?? "";
    expect(f).toMatch(/pipe/i);
    expect(f).toMatch(/last stage|final argument/i);
  });
});
