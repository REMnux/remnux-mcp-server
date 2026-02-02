/**
 * Unit tests for LocalConnector — runs real local processes.
 * No mocking, no MCP layer. Works on any dev machine.
 */

import { describe, it, expect } from "vitest";
import { LocalConnector } from "../connectors/local.js";
import { readFileSync, unlinkSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

describe("LocalConnector", () => {
  const connector = new LocalConnector();

  // ─── execute() ──────────────────────────────────────────────────────

  it("execute() runs a command and returns stdout", async () => {
    const result = await connector.execute(["echo", "hello"]);
    expect(result.stdout).toBe("hello");
    expect(result.exitCode).toBe(0);
  });

  it("execute() returns non-zero exit code on failure", async () => {
    const result = await connector.execute(["false"]);
    expect(result.exitCode).not.toBe(0);
  });

  it("execute() throws on empty command array", async () => {
    await expect(connector.execute([])).rejects.toThrow(
      "Command array cannot be empty",
    );
  });

  // ─── executeShell() ─────────────────────────────────────────────────

  it("executeShell() supports piped commands", async () => {
    const result = await connector.executeShell("echo hello | tr a-z A-Z");
    expect(result.stdout).toBe("HELLO");
    expect(result.exitCode).toBe(0);
  });

  it("executeShell() respects cwd option", async () => {
    const result = await connector.executeShell("pwd", { cwd: "/tmp" });
    // /tmp may resolve to /private/tmp on macOS
    expect(result.stdout).toMatch(/\/tmp/);
    expect(result.exitCode).toBe(0);
  });

  // ─── writeFile() ────────────────────────────────────────────────────

  it("writeFile() writes content to a file", async () => {
    const filePath = join(tmpdir(), `local-connector-test-${Date.now()}.txt`);
    const content = Buffer.from("test content from LocalConnector");

    try {
      await connector.writeFile(filePath, content);
      const written = readFileSync(filePath, "utf-8");
      expect(written).toBe("test content from LocalConnector");
    } finally {
      try {
        unlinkSync(filePath);
      } catch {
        // cleanup best-effort
      }
    }
  });

  // ─── disconnect() ──────────────────────────────────────────────────

  it("disconnect() is a no-op and does not throw", async () => {
    await expect(connector.disconnect()).resolves.toBeUndefined();
  });

  // ─── timeout ───────────────────────────────────────────────────────

  it("times out long-running commands", async () => {
    await expect(
      connector.execute(["sleep", "10"], { timeout: 500 }),
    ).rejects.toThrow(/timed out/i);
  });

  // ─── environment filtering ─────────────────────────────────────────

  it("filters environment variables to allowed list", async () => {
    // Set a var that should NOT be passed through
    process.env.SECRET_API_KEY = "leaked";

    try {
      const result = await connector.executeShell("env");
      expect(result.stdout).not.toContain("SECRET_API_KEY");
      // PATH should always be present
      expect(result.stdout).toContain("PATH=");
    } finally {
      delete process.env.SECRET_API_KEY;
    }
  });

  // ─── output truncation ────────────────────────────────────────────

  it("truncates output exceeding 10MB", async () => {
    // Generate ~11MB of output using pure shell (no python3 dependency)
    const result = await connector.executeShell(
      "dd if=/dev/zero bs=1024 count=11264 2>/dev/null | tr '\\0' 'A'",
    );
    expect(result.stdout).toContain("[OUTPUT TRUNCATED");
    // Should be roughly 10MB, not 12MB
    expect(result.stdout.length).toBeLessThan(11 * 1024 * 1024);
  }, 15_000);
});
