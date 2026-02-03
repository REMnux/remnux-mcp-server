/**
 * Integration tests for MCP tool handlers
 *
 * Tests all 7 tool handlers (run_tool, get_file_info, list_files,
 * extract_archive, upload_from_host, download_file, analyze_file) against a mock connector.
 *
 * Uses InMemoryTransport to invoke tools through the MCP protocol,
 * ensuring handlers are tested as wired in createServer().
 *
 * See: https://github.com/REMnux/remnux-mcp-server/issues/7
 */

import { describe, it, expect, vi, beforeAll, afterAll, beforeEach } from "vitest";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import type { Connector } from "../connectors/index.js";
import type { ServerConfig } from "../index.js";
import type { ToolResponse } from "../response.js";

vi.mock("fs", async (importOriginal) => {
  const actual = await importOriginal<typeof import("fs")>();
  return {
    ...actual,
    existsSync: vi.fn((p: string) => typeof p === "string" && p.startsWith("/tmp")),
    statSync: vi.fn(() => ({ isDirectory: () => true })),
  };
});

// ---------------------------------------------------------------------------
// Mock connector
// ---------------------------------------------------------------------------

const mockConnector = {
  execute: vi.fn(),
  executeShell: vi.fn(),
  writeFile: vi.fn(),
  writeFileFromPath: vi.fn(),
  readFileToPath: vi.fn(),
  disconnect: vi.fn(),
} satisfies Record<keyof Connector, ReturnType<typeof vi.fn>>;

// Mock createConnector to return our mock
vi.mock("../connectors/index.js", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../connectors/index.js")>();
  return {
    ...actual,
    createConnector: vi.fn().mockResolvedValue(mockConnector),
  };
});

// Mock extractArchive and detectArchiveType
vi.mock("../archive-extractor.js", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../archive-extractor.js")>();
  return {
    ...actual,
    detectArchiveType: actual.detectArchiveType,
    extractArchive: vi.fn(),
  };
});

// Mock uploadSampleFromHost (but keep validators real)
vi.mock("../file-upload.js", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../file-upload.js")>();
  return {
    ...actual,
    validateFilename: actual.validateFilename,
    validateHostPath: actual.validateHostPath,
    uploadSampleFromHost: vi.fn(),
  };
});

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

const testConfig: ServerConfig = {
  mode: "docker",
  container: "test-remnux",
  samplesDir: "/home/remnux/files/samples",
  outputDir: "/home/remnux/files/output",
  timeout: 300,
  noSandbox: false,
};

function ok(stdout: string, exitCode = 0) {
  return { stdout, stderr: "", exitCode };
}

// ---------------------------------------------------------------------------
// Setup: create MCP server + in-memory client
// ---------------------------------------------------------------------------

let client: Client;
let closeTransports: () => Promise<void>;

beforeAll(async () => {
  // Import after mocks are registered
  const { createServer } = await import("../index.js");
  const server = await createServer(testConfig);

  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();

  await server.connect(serverTransport);

  client = new Client({ name: "test-client", version: "1.0.0" });
  await client.connect(clientTransport);

  closeTransports = async () => {
    await clientTransport.close();
    await serverTransport.close();
  };
});

afterAll(async () => {
  await closeTransports?.();
});

beforeEach(() => {
  vi.mocked(mockConnector.execute).mockReset();
  vi.mocked(mockConnector.executeShell).mockReset();
  vi.mocked(mockConnector.writeFile).mockReset();
  vi.mocked(mockConnector.writeFileFromPath).mockReset();
  vi.mocked(mockConnector.readFileToPath).mockReset();
});

// Helper to call a tool and return the parsed envelope + raw isError
async function callTool(name: string, args: Record<string, unknown>): Promise<{ envelope: ToolResponse; isError?: boolean }> {
  const result = await client.callTool({ name, arguments: args });
  const textContent = (result.content as Array<{ type: string; text: string }>)[0];
  const envelope = JSON.parse(textContent.text) as ToolResponse;
  return { envelope, isError: result.isError as boolean | undefined };
}

// =========================================================================
// run_tool
// =========================================================================

describe("run_tool", () => {
  it("executes a simple command and returns structured response", async () => {
    vi.mocked(mockConnector.executeShell).mockResolvedValueOnce(ok("ELF 64-bit LSB"));

    const { envelope, isError } = await callTool("run_tool", { command: "file sample.exe" });

    expect(envelope.success).toBe(true);
    expect(envelope.tool).toBe("run_tool");
    expect(envelope.data.stdout).toBe("ELF 64-bit LSB");
    expect(envelope.data.exit_code).toBe(0);
    expect(envelope.metadata.elapsed_ms).toBeGreaterThanOrEqual(0);
    expect(isError).toBeFalsy();
    expect(mockConnector.executeShell).toHaveBeenCalledWith(
      "file sample.exe",
      expect.objectContaining({ cwd: testConfig.samplesDir }),
    );
  });

  it("appends quoted input_file path to command", async () => {
    vi.mocked(mockConnector.executeShell).mockResolvedValueOnce(ok("output"));

    await callTool("run_tool", { command: "pdfid.py --nozero", input_file: "suspect.pdf" });

    expect(mockConnector.executeShell).toHaveBeenCalledWith(
      `pdfid.py --nozero '${testConfig.samplesDir}/suspect.pdf'`,
      expect.anything(),
    );
  });

  it("blocks shell injection commands", async () => {
    const { envelope, isError } = await callTool("run_tool", { command: "eval malicious" });

    expect(isError).toBe(true);
    expect(envelope.success).toBe(false);
    expect(envelope.error).toMatch(/blocked/i);
    expect(mockConnector.executeShell).not.toHaveBeenCalled();
  });

  it("allows safe piped commands", async () => {
    vi.mocked(mockConnector.executeShell).mockResolvedValueOnce(ok("matched lines"));

    const { envelope } = await callTool("run_tool", { command: "strings file | grep foo" });

    expect(envelope.success).toBe(true);
    expect(envelope.data.stdout).toBe("matched lines");
    expect(mockConnector.executeShell).toHaveBeenCalled();
  });

  it("returns structured data on non-zero exit (no isError)", async () => {
    vi.mocked(mockConnector.executeShell).mockResolvedValueOnce({
      stdout: "partial output",
      stderr: "warning: something",
      exitCode: 1,
    });

    const { envelope, isError } = await callTool("run_tool", { command: "capa sample.exe" });

    expect(isError).toBeFalsy();
    expect(envelope.success).toBe(true);
    expect(envelope.data.stdout).toBe("partial output");
    expect(envelope.data.stderr).toBe("warning: something");
    expect(envelope.data.exit_code).toBe(1);
    expect(envelope.data.command).toBe("capa sample.exe");
  });

  it("blocks dangerous piped commands (pipe to bash)", async () => {
    const { envelope, isError } = await callTool("run_tool", { command: "strings file | bash" });

    expect(isError).toBe(true);
    expect(envelope.success).toBe(false);
    expect(envelope.error).toMatch(/blocked|dangerous/i);
    expect(mockConnector.executeShell).not.toHaveBeenCalled();
  });
});

// =========================================================================
// get_file_info
// =========================================================================

describe("get_file_info", () => {
  it("returns structured file info with parsed hashes", async () => {
    vi.mocked(mockConnector.execute)
      .mockResolvedValueOnce(ok("sample.exe: PE32 executable"))  // file
      .mockResolvedValueOnce(ok("abc123  sample.exe"))           // sha256sum
      .mockResolvedValueOnce(ok("def456  sample.exe"))           // md5sum
      .mockResolvedValueOnce(ok("aaa111  sample.exe"))           // sha1sum
      .mockResolvedValueOnce(ok("1024"));                        // stat -c %s

    const { envelope } = await callTool("get_file_info", { file: "sample.exe" });

    expect(envelope.success).toBe(true);
    expect(envelope.tool).toBe("get_file_info");
    expect(envelope.data.file_type).toContain("PE32 executable");
    expect(envelope.data.sha256).toBe("abc123");
    expect(envelope.data.md5).toBe("def456");
    expect(envelope.data.size_bytes).toBe(1024);
    expect(envelope.metadata.elapsed_ms).toBeGreaterThanOrEqual(0);
    expect(mockConnector.execute).toHaveBeenCalledTimes(5);
  });

  it("rejects path traversal attempts", async () => {
    const { envelope, isError } = await callTool("get_file_info", { file: "../etc/passwd" });

    expect(isError).toBe(true);
    expect(envelope.success).toBe(false);
    expect(mockConnector.execute).not.toHaveBeenCalled();
  });

  it("returns partial results when a command fails", async () => {
    vi.mocked(mockConnector.execute)
      .mockResolvedValueOnce(ok("sample.exe: data"))
      .mockRejectedValueOnce(new Error("sha256sum failed"))
      .mockResolvedValueOnce(ok("aaa111  sample.exe"))       // md5sum
      .mockResolvedValueOnce(ok("bbb222  sample.exe"))       // sha1sum
      .mockResolvedValueOnce(ok("512"));                     // stat

    const { envelope } = await callTool("get_file_info", { file: "sample.exe" });

    expect(envelope.success).toBe(true);
    expect(envelope.data.file_type).toContain("data");
    expect(envelope.data.md5).toBe("aaa111");
    expect(envelope.data.sha256).toBe("");
  });
});

// =========================================================================
// list_files
// =========================================================================

describe("list_files", () => {
  it("lists samples directory by default", async () => {
    vi.mocked(mockConnector.execute).mockResolvedValueOnce(ok("total 1\n-rw-r--r-- 1 remnux remnux 100 Jan 1 00:00 sample.exe"));

    const { envelope } = await callTool("list_files", { directory: "samples" });

    expect(envelope.success).toBe(true);
    expect(envelope.tool).toBe("list_files");
    expect(envelope.data.directory).toBe("samples");
    expect(envelope.data.path).toBe(testConfig.samplesDir);
    expect(envelope.data.entries).toEqual(
      expect.arrayContaining([expect.objectContaining({ name: "sample.exe" })])
    );
    expect(mockConnector.execute).toHaveBeenCalledWith(
      ["ls", "-la", testConfig.samplesDir],
      expect.anything(),
    );
  });

  it("lists output directory", async () => {
    vi.mocked(mockConnector.execute).mockResolvedValueOnce(ok("total 0"));

    const { envelope } = await callTool("list_files", { directory: "output" });

    expect(envelope.data.directory).toBe("output");
    expect(envelope.data.path).toBe(testConfig.outputDir);
    expect(mockConnector.execute).toHaveBeenCalledWith(
      ["ls", "-la", testConfig.outputDir],
      expect.anything(),
    );
  });
});

// =========================================================================
// extract_archive
// =========================================================================

describe("extract_archive", () => {
  it("rejects unsupported archive formats", async () => {
    const { envelope, isError } = await callTool("extract_archive", { archive_file: "data.tar.gz" });

    expect(isError).toBe(true);
    expect(envelope.success).toBe(false);
    expect(envelope.error).toMatch(/unsupported/i);
  });

  it("rejects path traversal in output_subdir", async () => {
    const { envelope, isError } = await callTool("extract_archive", { archive_file: "test.zip", output_subdir: "../escape" });

    expect(isError).toBe(true);
    expect(envelope.success).toBe(false);
    expect(envelope.error).toMatch(/invalid/i);
  });

  it("rejects shell metacharacters in output_subdir", async () => {
    const { envelope, isError } = await callTool("extract_archive", { archive_file: "test.zip", output_subdir: "dir;rm -rf" });

    expect(isError).toBe(true);
    expect(envelope.success).toBe(false);
    expect(envelope.error).toMatch(/invalid/i);
  });

  it("extracts valid .zip via extractArchive", async () => {
    const { extractArchive } = await import("../archive-extractor.js");
    vi.mocked(extractArchive).mockResolvedValueOnce({
      success: true,
      files: ["malware.exe", "readme.txt"],
      outputDir: "/home/remnux/files/samples/test",
      password: "infected",
    });

    const { envelope, isError } = await callTool("extract_archive", { archive_file: "test.zip" });

    expect(isError).toBeFalsy();
    expect(envelope.success).toBe(true);
    expect(envelope.tool).toBe("extract_archive");
    expect(envelope.data.file_count).toBe(2);
    expect(envelope.data.password_used).toBe("infected");
  });
});

// =========================================================================
// upload_from_host
// =========================================================================

describe("upload_from_host", () => {
  it("rejects relative paths", async () => {
    const { envelope, isError } = await callTool("upload_from_host", {
      host_path: "relative/path.exe",
    });

    expect(isError).toBe(true);
    expect(envelope.success).toBe(false);
  });

  it("rejects paths with shell metacharacters", async () => {
    const { envelope, isError } = await callTool("upload_from_host", {
      host_path: "/tmp/file;rm -rf /",
    });

    expect(isError).toBe(true);
    expect(envelope.success).toBe(false);
  });

  it("rejects invalid override filenames", async () => {
    const { envelope, isError } = await callTool("upload_from_host", {
      host_path: "/tmp/safe.exe",
      filename: "../evil.exe",
    });

    expect(isError).toBe(true);
    expect(envelope.success).toBe(false);
  });

  it("uploads valid file via uploadSampleFromHost", async () => {
    const { uploadSampleFromHost } = await import("../file-upload.js");
    vi.mocked(uploadSampleFromHost).mockResolvedValueOnce({
      success: true,
      path: "/home/remnux/files/samples/test.exe",
      size_bytes: 1024,
      sha256: "abcdef1234567890",
    });

    const { envelope, isError } = await callTool("upload_from_host", {
      host_path: "/tmp/test.exe",
    });

    expect(isError).toBeFalsy();
    expect(envelope.success).toBe(true);
    expect(envelope.tool).toBe("upload_from_host");
    expect(envelope.data.sha256).toBe("abcdef1234567890");
  });
});

// =========================================================================
// download_file
// =========================================================================

describe("download_file", () => {
  it("downloads a valid file and returns structured response (archived by default)", async () => {
    vi.mocked(mockConnector.execute)
      .mockResolvedValueOnce(ok("1024"))        // stat
      .mockResolvedValueOnce(ok("abc123  file")) // sha256sum
      .mockResolvedValueOnce(ok(""))             // zip command
      .mockResolvedValueOnce(ok(""));            // rm cleanup
    vi.mocked(mockConnector.readFileToPath).mockResolvedValueOnce(undefined);

    const { envelope, isError } = await callTool("download_file", {
      file_path: "result.json",
      output_path: "/tmp/downloads",
    });

    expect(isError).toBeFalsy();
    expect(envelope.success).toBe(true);
    expect(envelope.tool).toBe("download_file");
    expect(envelope.data.file_path).toBe("result.json");
    expect(envelope.data.size_bytes).toBe(1024);
    expect(envelope.data.sha256).toBe("abc123");
    expect(envelope.data.host_path).toBe("/tmp/downloads/result.json.zip");
    expect(envelope.data.archived).toBe(true);
    expect(envelope.data.archive_format).toBe("zip");
    expect(envelope.data.archive_password).toBe("infected");
  });

  it("downloads raw file with archive: false", async () => {
    vi.mocked(mockConnector.execute)
      .mockResolvedValueOnce(ok("1024"))        // stat
      .mockResolvedValueOnce(ok("abc123  file")); // sha256sum
    vi.mocked(mockConnector.readFileToPath).mockResolvedValueOnce(undefined);

    const { envelope, isError } = await callTool("download_file", {
      file_path: "result.json",
      output_path: "/tmp/downloads",
      archive: false,
    });

    expect(isError).toBeFalsy();
    expect(envelope.success).toBe(true);
    expect(envelope.data.host_path).toBe("/tmp/downloads/result.json");
    expect(envelope.data.archived).toBe(false);
  });

  it("rejects path traversal attempts", async () => {
    const { envelope, isError } = await callTool("download_file", {
      file_path: "../../etc/shadow",
      output_path: "/tmp/downloads",
    });

    expect(isError).toBe(true);
    expect(envelope.success).toBe(false);
    expect(mockConnector.execute).not.toHaveBeenCalled();
  });

  it("rejects invalid output_path", async () => {
    const { envelope, isError } = await callTool("download_file", {
      file_path: "result.json",
      output_path: "relative/path",
    });

    expect(isError).toBe(true);
    expect(envelope.success).toBe(false);
  });
});

// =========================================================================
// analyze_file
// =========================================================================

describe("analyze_file", () => {
  it("detects PE file and runs PE tools", async () => {
    // file command returns PE type
    vi.mocked(mockConnector.execute).mockResolvedValueOnce(
      ok("sample.exe: PE32 executable (GUI) Intel 80386, for MS Windows")
    );
    // Each tool runs via executeShell
    vi.mocked(mockConnector.executeShell)
      .mockResolvedValue(ok("tool output"));

    const { envelope, isError } = await callTool("analyze_file", { file: "sample.exe" });

    expect(isError).toBeFalsy();
    expect(envelope.success).toBe(true);
    expect(envelope.tool).toBe("analyze_file");
    expect(envelope.data.matched_category).toBe("PE");
    expect(envelope.data.detected_type).toContain("PE32");
    expect((envelope.data.tools_run as Array<{ name: string }>).length).toBeGreaterThan(0);
    expect((envelope.data.tools_run as Array<{ name: string }>)[0].name).toBe("peframe");
  });

  it("detects PDF and runs PDF tools", async () => {
    vi.mocked(mockConnector.execute).mockResolvedValueOnce(
      ok("report.pdf: PDF document, version 1.7")
    );
    vi.mocked(mockConnector.executeShell).mockResolvedValue(ok("pdf output"));

    const { envelope } = await callTool("analyze_file", { file: "report.pdf" });

    expect(envelope.data.matched_category).toBe("PDF");
    expect((envelope.data.tools_run as Array<{ name: string }>).some((t) => t.name === "pdfid")).toBe(true);
  });

  it("falls back to Unknown for unrecognized types", async () => {
    vi.mocked(mockConnector.execute).mockResolvedValueOnce(ok("mystery.dat: data"));
    vi.mocked(mockConnector.executeShell).mockResolvedValue(ok("strings output"));

    const { envelope } = await callTool("analyze_file", { file: "mystery.dat" });

    expect(envelope.data.matched_category).toBe("Unknown");
    expect((envelope.data.tools_run as Array<{ name: string }>).some((t) => t.name === "strings")).toBe(true);
  });

  it("reports tools not found as skipped", async () => {
    vi.mocked(mockConnector.execute).mockResolvedValueOnce(
      ok("sample.exe: PE32 executable")
    );
    // Preprocessing detect calls (debloat, pyinstxtractor) return non-zero (not applicable)
    // Then first tool not found, rest succeed
    vi.mocked(mockConnector.executeShell)
      .mockResolvedValueOnce({ stdout: "", stderr: "", exitCode: 1 })  // debloat detect
      .mockResolvedValueOnce({ stdout: "", stderr: "", exitCode: 1 })  // pyinstxtractor detect
      .mockResolvedValueOnce({ stdout: "", stderr: "peframe: command not found", exitCode: 127 })
      .mockResolvedValue(ok("output"));

    const { envelope } = await callTool("analyze_file", { file: "sample.exe" });

    expect((envelope.data.tools_skipped as Array<{ name: string }>).length).toBe(1);
    expect((envelope.data.tools_skipped as Array<{ name: string }>)[0].name).toBe("peframe");
  });

  it("reports timed-out tools as failed", async () => {
    vi.mocked(mockConnector.execute).mockResolvedValueOnce(
      ok("sample.exe: PE32 executable")
    );
    // Preprocessing detect calls (debloat, pyinstxtractor) return non-zero (not applicable)
    vi.mocked(mockConnector.executeShell)
      .mockResolvedValueOnce({ stdout: "", stderr: "", exitCode: 1 })  // debloat detect
      .mockResolvedValueOnce({ stdout: "", stderr: "", exitCode: 1 })  // pyinstxtractor detect
      .mockRejectedValueOnce(new Error("Command timeout"))
      .mockResolvedValue(ok("output"));

    const { envelope } = await callTool("analyze_file", { file: "sample.exe" });

    expect((envelope.data.tools_failed as Array<{ error: string }>).length).toBe(1);
    expect((envelope.data.tools_failed as Array<{ error: string }>)[0].error).toBe("Timed out");
  });

  it("rejects path traversal attempts", async () => {
    const { envelope, isError } = await callTool("analyze_file", { file: "../etc/passwd" });

    expect(isError).toBe(true);
    expect(envelope.success).toBe(false);
    expect(mockConnector.execute).not.toHaveBeenCalled();
  });

  it("returns error when file command fails", async () => {
    vi.mocked(mockConnector.execute).mockRejectedValueOnce(new Error("No such file"));

    const { envelope, isError } = await callTool("analyze_file", { file: "nonexistent.bin" });

    expect(isError).toBe(true);
    expect(envelope.success).toBe(false);
  });
});

// =========================================================================
// extract_iocs
// =========================================================================

describe("extract_iocs", () => {
  it("extracts IOCs from text and returns structured response", async () => {
    const text = "C2 at 45.33.32.156 hash aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d";

    const { envelope, isError } = await callTool("extract_iocs", { text });

    expect(isError).toBeFalsy();
    expect(envelope.success).toBe(true);
    expect(envelope.tool).toBe("extract_iocs");
    expect((envelope.data.iocs as Array<{ type: string }>).length).toBeGreaterThan(0);
    expect(envelope.data.summary).toBeDefined();
    // noise not included by default
    expect(envelope.data.noise).toBeUndefined();
  });

  it("returns empty result for text with no IOCs", async () => {
    const { envelope, isError } = await callTool("extract_iocs", { text: "nothing here" });

    expect(isError).toBeFalsy();
    expect(envelope.success).toBe(true);
    expect((envelope.data.iocs as unknown[]).length).toBe(0);
    expect((envelope.data.summary as { total: number }).total).toBe(0);
  });

  it("includes noise when include_noise is true", async () => {
    const text = "internal server 192.168.1.1 and google.com";

    const { envelope } = await callTool("extract_iocs", { text, include_noise: true });

    expect(envelope.success).toBe(true);
    expect(envelope.data.noise).toBeDefined();
    expect((envelope.data.noise as unknown[]).length).toBeGreaterThan(0);
  });
});

// =========================================================================
// Envelope structure validation (cross-tool)
// =========================================================================

describe("response envelope", () => {
  it("every success response has required envelope fields", async () => {
    vi.mocked(mockConnector.execute).mockResolvedValue(ok("total 0"));

    const { envelope } = await callTool("list_files", { directory: "samples" });

    expect(envelope).toHaveProperty("success");
    expect(envelope).toHaveProperty("tool");
    expect(envelope).toHaveProperty("data");
    expect(envelope).toHaveProperty("metadata");
    expect(envelope.metadata).toHaveProperty("elapsed_ms");
    expect(typeof envelope.metadata.elapsed_ms).toBe("number");
  });

  it("every error response has required envelope fields", async () => {
    const { envelope } = await callTool("run_tool", { command: "sudo rm -rf /" });

    expect(envelope.success).toBe(false);
    expect(envelope.tool).toBe("run_tool");
    expect(envelope.error).toBeDefined();
    expect(envelope.metadata.elapsed_ms).toBeGreaterThanOrEqual(0);
  });
});
