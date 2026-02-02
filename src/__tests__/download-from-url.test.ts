/**
 * Unit tests for download_from_url handler
 */

import { describe, it, expect, vi, beforeEach } from "vitest";
import { validateUrl, validateHeader, deriveFilename } from "../handlers/download-from-url.js";
import type { Connector } from "../connectors/index.js";
import type { HandlerDeps } from "../handlers/types.js";
import { SessionState } from "../state/session.js";

// ---------------------------------------------------------------------------
// URL validation
// ---------------------------------------------------------------------------

describe("validateUrl", () => {
  it("accepts http URLs", () => {
    expect(validateUrl("http://example.com/file.exe")).toEqual({ valid: true });
  });

  it("accepts https URLs", () => {
    expect(validateUrl("https://example.com/malware.zip")).toEqual({ valid: true });
  });

  it("rejects ftp://", () => {
    const r = validateUrl("ftp://evil.com/file");
    expect(r.valid).toBe(false);
    expect(r.error).toMatch(/Unsupported protocol/);
  });

  it("rejects file://", () => {
    const r = validateUrl("file:///etc/passwd");
    expect(r.valid).toBe(false);
    expect(r.error).toMatch(/Unsupported protocol/);
  });

  it("rejects URLs with single quotes", () => {
    const r = validateUrl("https://example.com/path'injection");
    expect(r.valid).toBe(false);
    expect(r.error).toMatch(/invalid characters/);
  });

  it("rejects URLs with newlines", () => {
    const r = validateUrl("https://example.com/path\ninjection");
    expect(r.valid).toBe(false);
    expect(r.error).toMatch(/invalid characters/);
  });

  it("rejects URLs with null bytes", () => {
    const r = validateUrl("https://example.com/\x00path");
    expect(r.valid).toBe(false);
    expect(r.error).toMatch(/invalid characters/);
  });

  it("rejects invalid URLs", () => {
    const r = validateUrl("not a url");
    expect(r.valid).toBe(false);
    expect(r.error).toMatch(/Invalid URL/);
  });
});

// ---------------------------------------------------------------------------
// Header validation
// ---------------------------------------------------------------------------

describe("validateHeader", () => {
  it("accepts well-formed headers", () => {
    expect(validateHeader("User-Agent: Mozilla/5.0")).toEqual({ valid: true });
    expect(validateHeader("X-Auth-Token: abc123")).toEqual({ valid: true });
    expect(validateHeader("Accept: application/json")).toEqual({ valid: true });
  });

  it("rejects headers without colon", () => {
    const r = validateHeader("NoColonHere");
    expect(r.valid).toBe(false);
    expect(r.error).toMatch(/Invalid header format/);
  });

  it("rejects headers with newlines", () => {
    const r = validateHeader("X-Evil: value\r\nInjected: header");
    expect(r.valid).toBe(false);
    expect(r.error).toMatch(/invalid characters/);
  });

  it("rejects headers with single quotes", () => {
    const r = validateHeader("X-Evil: val'ue");
    expect(r.valid).toBe(false);
    expect(r.error).toMatch(/invalid characters/);
  });

  it("rejects headers with null bytes", () => {
    const r = validateHeader("X-Evil: val\x00ue");
    expect(r.valid).toBe(false);
    expect(r.error).toMatch(/invalid characters/);
  });
});

// ---------------------------------------------------------------------------
// Filename derivation
// ---------------------------------------------------------------------------

describe("deriveFilename", () => {
  it("extracts filename from URL path", () => {
    expect(deriveFilename("https://example.com/malware.exe")).toBe("malware.exe");
  });

  it("extracts filename ignoring query params", () => {
    expect(deriveFilename("https://example.com/file.zip?token=abc")).toBe("file.zip");
  });

  it("falls back to downloaded_sample for root path", () => {
    expect(deriveFilename("https://example.com/")).toBe("downloaded_sample");
  });

  it("falls back to downloaded_sample for empty path", () => {
    expect(deriveFilename("https://example.com")).toBe("downloaded_sample");
  });

  it("decodes URL-encoded characters", () => {
    expect(deriveFilename("https://example.com/my%20malware.exe")).toBe("my malware.exe");
  });

  it("handles invalid percent-encoding gracefully", () => {
    expect(deriveFilename("https://example.com/file%ZZname.exe")).toBe("file%ZZname.exe");
  });
});

// ---------------------------------------------------------------------------
// Handler integration (mocked connector)
// ---------------------------------------------------------------------------

describe("handleDownloadFromUrl", () => {
  let mockConnector: Record<keyof Connector, ReturnType<typeof vi.fn>>;
  let deps: HandlerDeps;

  beforeEach(() => {
    mockConnector = {
      execute: vi.fn(),
      executeShell: vi.fn(),
      writeFile: vi.fn(),
      writeFileFromPath: vi.fn(),
      readFileToPath: vi.fn(),
      disconnect: vi.fn(),
    };

    deps = {
      connector: mockConnector as unknown as Connector,
      config: {
        samplesDir: "/home/remnux/files/samples",
        outputDir: "/home/remnux/files/output",
        timeout: 300,
        noSandbox: false,
        mode: "docker",
      },
      sessionState: new SessionState(),
    };
  });

  // Dynamically import to avoid hoisting issues
  async function callHandler(args: Record<string, unknown>) {
    const { handleDownloadFromUrl } = await import("../handlers/download-from-url.js");
    return handleDownloadFromUrl(deps, args as never);
  }

  it("rejects ftp:// URLs", async () => {
    const result = await callHandler({ url: "ftp://evil.com/file" });
    const envelope = JSON.parse(result.content[0].text);
    expect(envelope.success).toBe(false);
    expect(envelope.error_code).toBe("INVALID_URL");
  });

  it("rejects invalid headers", async () => {
    const result = await callHandler({
      url: "https://example.com/file.exe",
      headers: ["BadHeader"],
    });
    const envelope = JSON.parse(result.content[0].text);
    expect(envelope.success).toBe(false);
    expect(envelope.error_code).toBe("INVALID_HEADER");
  });

  it("builds correct curl command for successful download", async () => {
    // File doesn't exist
    mockConnector.execute.mockImplementation(async (cmd: string[]) => {
      if (cmd[0] === "test") return { exitCode: 1, stdout: "", stderr: "" };
      if (cmd[0] === "mkdir") return { exitCode: 0, stdout: "", stderr: "" };
      if (cmd[0] === "file") return { exitCode: 0, stdout: "PE32 executable", stderr: "" };
      if (cmd[0] === "sha256sum") return { exitCode: 0, stdout: "abc123  file", stderr: "" };
      if (cmd[0] === "md5sum") return { exitCode: 0, stdout: "def456  file", stderr: "" };
      if (cmd[0] === "sha1sum") return { exitCode: 0, stdout: "789abc  file", stderr: "" };
      if (cmd[0] === "stat") return { exitCode: 0, stdout: "1024", stderr: "" };
      return { exitCode: 0, stdout: "", stderr: "" };
    });
    mockConnector.executeShell.mockResolvedValue({ exitCode: 0, stdout: "", stderr: "" });

    const result = await callHandler({
      url: "https://example.com/malware.exe",
      headers: ["User-Agent: Mozilla/5.0"],
    });

    // Check curl was called with expected flags
    const shellCall = mockConnector.executeShell.mock.calls[0][0] as string;
    expect(shellCall).toContain("curl -sSfL");
    expect(shellCall).toContain("--max-filesize");
    expect(shellCall).toContain("-H 'User-Agent: Mozilla/5.0'");
    expect(shellCall).toContain("'https://example.com/malware.exe'");

    const envelope = JSON.parse(result.content[0].text);
    expect(envelope.success).toBe(true);
    expect(envelope.data.method).toBe("curl");
    expect(envelope.data.sha256).toBe("abc123");
    expect(envelope.data.file).toBe("malware.exe");
  });

  it("returns error on curl failure with descriptive message", async () => {
    mockConnector.execute.mockImplementation(async (cmd: string[]) => {
      if (cmd[0] === "test") return { exitCode: 1, stdout: "", stderr: "" };
      if (cmd[0] === "mkdir") return { exitCode: 0, stdout: "", stderr: "" };
      return { exitCode: 0, stdout: "", stderr: "" };
    });
    // curl exit code 22 = HTTP error
    mockConnector.executeShell.mockResolvedValue({ exitCode: 22, stdout: "", stderr: "404 Not Found" });

    const result = await callHandler({ url: "https://example.com/missing.exe" });
    const envelope = JSON.parse(result.content[0].text);
    expect(envelope.success).toBe(false);
    expect(envelope.error).toMatch(/HTTP error/);
  });

  it("reports file-already-exists when overwrite is false", async () => {
    mockConnector.execute.mockImplementation(async (cmd: string[]) => {
      if (cmd[0] === "test") return { exitCode: 0, stdout: "", stderr: "" }; // file exists
      return { exitCode: 0, stdout: "", stderr: "" };
    });

    const result = await callHandler({ url: "https://example.com/file.exe", overwrite: false });
    const envelope = JSON.parse(result.content[0].text);
    expect(envelope.success).toBe(false);
    expect(envelope.error_code).toBe("FILE_EXISTS");
  });

  it("constructs thug command with user-agent flag", async () => {
    // File doesn't exist
    mockConnector.execute.mockImplementation(async (cmd: string[]) => {
      if (cmd[0] === "test") return { exitCode: 1, stdout: "", stderr: "" };
      if (cmd[0] === "mkdir") return { exitCode: 0, stdout: "", stderr: "" };
      if (cmd[0] === "file") return { exitCode: 0, stdout: "PE32 executable", stderr: "" };
      if (cmd[0] === "sha256sum") return { exitCode: 0, stdout: "abc123  file", stderr: "" };
      if (cmd[0] === "md5sum") return { exitCode: 0, stdout: "def456  file", stderr: "" };
      if (cmd[0] === "sha1sum") return { exitCode: 0, stdout: "789abc  file", stderr: "" };
      if (cmd[0] === "stat") return { exitCode: 0, stdout: "2048", stderr: "" };
      return { exitCode: 0, stdout: "", stderr: "" };
    });

    // First executeShell = thug, second = find, third = cp
    mockConnector.executeShell
      .mockResolvedValueOnce({ exitCode: 0, stdout: "", stderr: "" }) // thug
      .mockResolvedValueOnce({ exitCode: 0, stdout: "/output/thug-123/application/x-dosexec/sample.exe\n", stderr: "" }) // find
      .mockResolvedValueOnce({ exitCode: 0, stdout: "", stderr: "" }); // cp

    const result = await callHandler({
      url: "https://malicious-site.com/landing",
      method: "thug",
      filename: "landing-payload.exe",
      headers: ["User-Agent: Mozilla/5.0", "X-Custom: ignored"],
    });

    // Check thug command
    const thugCall = mockConnector.executeShell.mock.calls[0][0] as string;
    expect(thugCall).toContain("thug");
    expect(thugCall).toContain("-u 'Mozilla/5.0'");
    expect(thugCall).toContain("'https://malicious-site.com/landing'");

    const envelope = JSON.parse(result.content[0].text);
    expect(envelope.success).toBe(true);
    expect(envelope.data.method).toBe("thug");
    expect(envelope.data.warnings).toBeDefined();
    expect(envelope.data.warnings[0]).toMatch(/X-Custom/);
  });

  it("allows overwrite when overwrite=true", async () => {
    mockConnector.execute.mockImplementation(async (cmd: string[]) => {
      if (cmd[0] === "test") return { exitCode: 0, stdout: "", stderr: "" }; // file exists
      if (cmd[0] === "mkdir") return { exitCode: 0, stdout: "", stderr: "" };
      if (cmd[0] === "file") return { exitCode: 0, stdout: "PE32 executable", stderr: "" };
      if (cmd[0] === "sha256sum") return { exitCode: 0, stdout: "abc123  file", stderr: "" };
      if (cmd[0] === "md5sum") return { exitCode: 0, stdout: "def456  file", stderr: "" };
      if (cmd[0] === "sha1sum") return { exitCode: 0, stdout: "789abc  file", stderr: "" };
      if (cmd[0] === "stat") return { exitCode: 0, stdout: "1024", stderr: "" };
      return { exitCode: 0, stdout: "", stderr: "" };
    });
    mockConnector.executeShell.mockResolvedValue({ exitCode: 0, stdout: "", stderr: "" });

    const result = await callHandler({
      url: "https://example.com/file.exe",
      overwrite: true,
    });
    const envelope = JSON.parse(result.content[0].text);
    expect(envelope.success).toBe(true);
  });

  it("handles URLs with $ characters without false positive blocking", async () => {
    mockConnector.execute.mockImplementation(async (cmd: string[]) => {
      if (cmd[0] === "test") return { exitCode: 1, stdout: "", stderr: "" };
      if (cmd[0] === "mkdir") return { exitCode: 0, stdout: "", stderr: "" };
      if (cmd[0] === "file") return { exitCode: 0, stdout: "data", stderr: "" };
      if (cmd[0] === "sha256sum") return { exitCode: 0, stdout: "aaa  file", stderr: "" };
      if (cmd[0] === "md5sum") return { exitCode: 0, stdout: "bbb  file", stderr: "" };
      if (cmd[0] === "sha1sum") return { exitCode: 0, stdout: "ccc  file", stderr: "" };
      if (cmd[0] === "stat") return { exitCode: 0, stdout: "512", stderr: "" };
      return { exitCode: 0, stdout: "", stderr: "" };
    });
    mockConnector.executeShell.mockResolvedValue({ exitCode: 0, stdout: "", stderr: "" });

    const result = await callHandler({
      url: "https://example.com/download?token=$abc&id=123",
    });
    const envelope = JSON.parse(result.content[0].text);
    // Should succeed — $ in URL must not trigger blocklist rejection
    expect(envelope.success).toBe(true);
    expect(envelope.data.method).toBe("curl");
  });

  it("cleans up partial file on curl failure", async () => {
    mockConnector.execute.mockImplementation(async (cmd: string[]) => {
      if (cmd[0] === "test") return { exitCode: 1, stdout: "", stderr: "" };
      if (cmd[0] === "mkdir") return { exitCode: 0, stdout: "", stderr: "" };
      if (cmd[0] === "rm") return { exitCode: 0, stdout: "", stderr: "" };
      return { exitCode: 0, stdout: "", stderr: "" };
    });
    mockConnector.executeShell.mockResolvedValue({ exitCode: 28, stdout: "", stderr: "timeout" });

    const result = await callHandler({ url: "https://example.com/big.bin" });
    const envelope = JSON.parse(result.content[0].text);
    expect(envelope.success).toBe(false);
    expect(envelope.error).toMatch(/timed out/i);

    // Verify rm -f was called for cleanup
    const rmCalls = mockConnector.execute.mock.calls.filter(
      (c: string[][]) => c[0][0] === "rm"
    );
    expect(rmCalls.length).toBe(1);
  });
});
