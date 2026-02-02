import { describe, it, expect, vi } from "vitest";
import { handleDownloadFile } from "../download-file.js";
import { createMockDeps, ok, parseEnvelope } from "./helpers.js";

vi.mock("fs", async (importOriginal) => {
  const actual = await importOriginal<typeof import("fs")>();
  return {
    ...actual,
    existsSync: vi.fn((p: string) => p.startsWith("/tmp")),
    statSync: vi.fn(() => ({ isDirectory: () => true })),
  };
});

describe("handleDownloadFile", () => {
  it("archives by default (archive: true)", async () => {
    const deps = createMockDeps();
    const exec = vi.mocked(deps.connector.execute);
    const readToPath = vi.mocked(deps.connector.readFileToPath);

    exec
      .mockResolvedValueOnce(ok("1024"))                       // stat
      .mockResolvedValueOnce(ok("abc123  /output/file.bin"))   // sha256sum
      .mockResolvedValueOnce(ok(""))                           // zip command
      .mockResolvedValueOnce(ok(""));                          // rm cleanup
    readToPath.mockResolvedValueOnce(undefined);

    const result = await handleDownloadFile(deps, {
      file_path: "file.bin",
      output_path: "/tmp/downloads",
    });
    const env = parseEnvelope(result);
    expect(env.success).toBe(true);
    expect(env.data.archived).toBe(true);
    expect(env.data.archive_format).toBe("zip");
    expect(env.data.archive_password).toBe("infected");
    expect(env.data.host_path).toBe("/tmp/downloads/file.bin.zip");
    expect(env.data.sha256).toBe("abc123");

    // Verify zip command was called
    const zipCall = exec.mock.calls[2];
    expect(zipCall[0][0]).toBe("zip");
    expect(zipCall[0]).toContain("-P");
    expect(zipCall[0]).toContain("infected");
  });

  it("downloads raw file when archive: false", async () => {
    const deps = createMockDeps();
    const exec = vi.mocked(deps.connector.execute);
    const readToPath = vi.mocked(deps.connector.readFileToPath);

    exec
      .mockResolvedValueOnce(ok("1024"))                       // stat
      .mockResolvedValueOnce(ok("abc123  /output/file.bin"));  // sha256sum
    readToPath.mockResolvedValueOnce(undefined);

    const result = await handleDownloadFile(deps, {
      file_path: "file.bin",
      output_path: "/tmp/downloads",
      archive: false,
    });
    const env = parseEnvelope(result);
    expect(env.success).toBe(true);
    expect(env.data.host_path).toBe("/tmp/downloads/file.bin");
    expect(env.data.archived).toBe(false);
    expect(env.data.archive_format).toBeUndefined();
    expect(env.data.archive_password).toBeUndefined();
    expect(readToPath).toHaveBeenCalledWith("/output/file.bin", "/tmp/downloads/file.bin");
  });

  it("uses session archive metadata when available", async () => {
    const deps = createMockDeps();
    // Store metadata as if extract_archive ran previously with 7z + "malware" password
    deps.sessionState.storeArchiveInfo("sample.7z", ["payload.exe"], "7z", "malware");

    const exec = vi.mocked(deps.connector.execute);
    const readToPath = vi.mocked(deps.connector.readFileToPath);

    exec
      .mockResolvedValueOnce(ok("2048"))                           // stat
      .mockResolvedValueOnce(ok("def456  /output/payload.exe"))    // sha256sum
      .mockResolvedValueOnce(ok(""))                               // 7z command
      .mockResolvedValueOnce(ok(""));                              // rm cleanup
    readToPath.mockResolvedValueOnce(undefined);

    const result = await handleDownloadFile(deps, {
      file_path: "payload.exe",
      output_path: "/tmp/downloads",
    });
    const env = parseEnvelope(result);
    expect(env.success).toBe(true);
    expect(env.data.archived).toBe(true);
    expect(env.data.archive_format).toBe("7z");
    expect(env.data.archive_password).toBe("malware");
    expect(env.data.host_path).toBe("/tmp/downloads/payload.exe.7z");

    // Verify 7z command was called
    const archiveCall = exec.mock.calls[2];
    expect(archiveCall[0][0]).toBe("7z");
    expect(archiveCall[0]).toContain("-pmalware");
  });

  it("returns error when archive creation fails", async () => {
    const deps = createMockDeps();
    const exec = vi.mocked(deps.connector.execute);

    exec
      .mockResolvedValueOnce(ok("1024"))                       // stat
      .mockResolvedValueOnce(ok("abc123  /output/file.bin"))   // sha256sum
      .mockResolvedValueOnce({ stdout: "", stderr: "zip not found", exitCode: 127 }); // zip fails

    const result = await handleDownloadFile(deps, {
      file_path: "file.bin",
      output_path: "/tmp/downloads",
    });
    const env = parseEnvelope(result);
    expect(env.success).toBe(false);
    expect(env.error_code).toBe("ARCHIVE_FAILED");
  });

  it("cleans up temp archive even if transfer fails", async () => {
    const deps = createMockDeps();
    const exec = vi.mocked(deps.connector.execute);
    const readToPath = vi.mocked(deps.connector.readFileToPath);

    exec
      .mockResolvedValueOnce(ok("1024"))                       // stat
      .mockResolvedValueOnce(ok("abc123  /output/file.bin"))   // sha256sum
      .mockResolvedValueOnce(ok(""))                           // zip command
      .mockResolvedValueOnce(ok(""));                          // rm cleanup
    readToPath.mockRejectedValueOnce(new Error("transfer failed"));

    const result = await handleDownloadFile(deps, {
      file_path: "file.bin",
      output_path: "/tmp/downloads",
    });
    const env = parseEnvelope(result);
    expect(env.success).toBe(false);

    // Verify cleanup was attempted (rm -f call)
    const rmCall = exec.mock.calls[3];
    expect(rmCall[0][0]).toBe("rm");
    expect(rmCall[0][1]).toBe("-f");
  });

  it("rejects archive password with shell metacharacters", async () => {
    const deps = createMockDeps();
    // Store metadata with a malicious password containing shell metacharacters
    deps.sessionState.storeArchiveInfo("evil.zip", ["payload.exe"], "zip", "pass;rm -rf /");

    const exec = vi.mocked(deps.connector.execute);
    exec
      .mockResolvedValueOnce(ok("1024"))                       // stat
      .mockResolvedValueOnce(ok("abc123  /output/payload.exe")); // sha256sum

    const result = await handleDownloadFile(deps, {
      file_path: "payload.exe",
      output_path: "/tmp/downloads",
    });
    const env = parseEnvelope(result);
    expect(env.success).toBe(false);
    expect(env.error_code).toBe("INVALID_PASSWORD");
  });

  it("rejects invalid output_path", async () => {
    const deps = createMockDeps();

    const result = await handleDownloadFile(deps, {
      file_path: "file.bin",
      output_path: "relative/path",
    });
    const env = parseEnvelope(result);
    expect(env.success).toBe(false);
    expect(env.error_code).toBe("INVALID_PATH");
  });

  it("handles sha256sum failure gracefully (returns 'unknown')", async () => {
    const deps = createMockDeps();
    const exec = vi.mocked(deps.connector.execute);

    exec
      .mockResolvedValueOnce(ok("100"))       // stat
      .mockResolvedValueOnce(ok(""))           // sha256sum empty output
      .mockResolvedValueOnce(ok(""))           // zip
      .mockResolvedValueOnce(ok(""));          // rm cleanup
    vi.mocked(deps.connector.readFileToPath).mockResolvedValueOnce(undefined);

    const result = await handleDownloadFile(deps, {
      file_path: "file.bin",
      output_path: "/tmp/downloads",
    });
    const env = parseEnvelope(result);
    expect(env.success).toBe(true);
    expect(env.data.sha256).toBe("unknown");
  });

  it("skips path validation when noSandbox is true", async () => {
    const deps = createMockDeps({ noSandbox: true });
    const exec = vi.mocked(deps.connector.execute);

    exec
      .mockResolvedValueOnce(ok("100"))
      .mockResolvedValueOnce(ok("abc  file"))
      .mockResolvedValueOnce(ok(""))           // zip
      .mockResolvedValueOnce(ok(""));          // rm cleanup
    vi.mocked(deps.connector.readFileToPath).mockResolvedValueOnce(undefined);

    const result = await handleDownloadFile(deps, {
      file_path: "../../etc/passwd",
      output_path: "/tmp/downloads",
    });
    const env = parseEnvelope(result);
    expect(env.success).toBe(true);
  });

  it("rejects files exceeding 200MB", async () => {
    const deps = createMockDeps();
    const exec = vi.mocked(deps.connector.execute);

    const bigSize = String(201 * 1024 * 1024);
    exec
      .mockResolvedValueOnce(ok(bigSize))
      .mockResolvedValueOnce(ok("abc  file"));

    const result = await handleDownloadFile(deps, {
      file_path: "file.bin",
      output_path: "/tmp/downloads",
    });
    const env = parseEnvelope(result);
    expect(env.success).toBe(false);
    expect(env.error_code).toBe("FILE_TOO_LARGE");
  });

  it("rejects non-existent output directory", async () => {
    const { existsSync } = await import("fs");
    vi.mocked(existsSync).mockReturnValueOnce(false);

    const deps = createMockDeps();
    const result = await handleDownloadFile(deps, {
      file_path: "file.bin",
      output_path: "/nonexistent/dir",
    });
    const env = parseEnvelope(result);
    expect(env.success).toBe(false);
    expect(env.error_code).toBe("INVALID_PATH");
  });

  it("uses basename when file_path contains subdirectory", async () => {
    const deps = createMockDeps();
    const exec = vi.mocked(deps.connector.execute);
    const readToPath = vi.mocked(deps.connector.readFileToPath);

    exec
      .mockResolvedValueOnce(ok("512"))
      .mockResolvedValueOnce(ok("def456  /output/subdir/result.json"))
      .mockResolvedValueOnce(ok(""))           // zip
      .mockResolvedValueOnce(ok(""));          // rm cleanup
    readToPath.mockResolvedValueOnce(undefined);

    const result = await handleDownloadFile(deps, {
      file_path: "subdir/result.json",
      output_path: "/tmp/downloads",
    });
    const env = parseEnvelope(result);
    expect(env.success).toBe(true);
    expect(env.data.host_path).toBe("/tmp/downloads/result.json.zip");
  });

  it("wraps connector errors", async () => {
    const deps = createMockDeps();
    vi.mocked(deps.connector.execute).mockRejectedValue(new Error("connection lost"));

    const result = await handleDownloadFile(deps, {
      file_path: "file.bin",
      output_path: "/tmp/downloads",
    });
    const env = parseEnvelope(result);
    expect(env.success).toBe(false);
    expect(result.isError).toBe(true);
  });
});
