import { describe, it, expect, vi, afterAll } from "vitest";
import { mkdtempSync, mkdirSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { handleDownloadFile } from "../download-file.js";
import { createMockDeps, ok, parseEnvelope } from "./helpers.js";

vi.mock("fs", async (importOriginal) => {
  const actual = await importOriginal<typeof import("fs")>();
  return {
    ...actual,
    existsSync: vi.fn((p: string) => p.startsWith("/tmp") || actual.existsSync(p)),
    statSync: vi.fn(() => ({ isDirectory: () => true })),
  };
});

// A real host directory: with --sandbox on (the mock default), download_file
// confines output_path to the ingest root by realpath, so the directory has to
// exist. Destination checks (symlink, existing file) use the real lstat too.
const tempDirs: string[] = [];
const makeTempDir = (prefix: string) => {
  const dir = mkdtempSync(join(tmpdir(), prefix));
  tempDirs.push(dir);
  return dir;
};
const hostDir = makeTempDir("download-file-test-");
const sandboxedDeps = () => createMockDeps({ ingestRoot: hostDir });

afterAll(() => {
  // Remove only the directories this file created.
  for (const dir of tempDirs) rmSync(dir, { recursive: true, force: true });
});

describe("handleDownloadFile", () => {
  it("archives by default (archive: true)", async () => {
    const deps = sandboxedDeps();
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
      output_path: hostDir,
    });
    const env = parseEnvelope(result);
    expect(env.success).toBe(true);
    expect(env.data.archived).toBe(true);
    expect(env.data.archive_format).toBe("zip");
    expect(env.data.archive_password).toBe("infected");
    expect(env.data.host_path).toBe(`${hostDir}/file.bin.zip`);
    expect(env.data.sha256).toBe("abc123");

    // Verify zip command was called
    const zipCall = exec.mock.calls[2];
    expect(zipCall[0][0]).toBe("zip");
    expect(zipCall[0]).toContain("-P");
    expect(zipCall[0]).toContain("infected");
  });

  it("downloads raw file when archive: false", async () => {
    const deps = sandboxedDeps();
    const exec = vi.mocked(deps.connector.execute);
    const readToPath = vi.mocked(deps.connector.readFileToPath);

    exec
      .mockResolvedValueOnce(ok("1024"))                       // stat
      .mockResolvedValueOnce(ok("abc123  /output/file.bin"));  // sha256sum
    readToPath.mockResolvedValueOnce(undefined);

    const result = await handleDownloadFile(deps, {
      file_path: "file.bin",
      output_path: hostDir,
      archive: false,
    });
    const env = parseEnvelope(result);
    expect(env.success).toBe(true);
    expect(env.data.host_path).toBe(`${hostDir}/file.bin`);
    expect(env.data.archived).toBe(false);
    expect(env.data.archive_format).toBeUndefined();
    expect(env.data.archive_password).toBeUndefined();
    expect(readToPath).toHaveBeenCalledWith("/output/file.bin", `${hostDir}/file.bin`);
  });

  it("uses session archive metadata when available", async () => {
    const deps = sandboxedDeps();
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
      output_path: hostDir,
    });
    const env = parseEnvelope(result);
    expect(env.success).toBe(true);
    expect(env.data.archived).toBe(true);
    expect(env.data.archive_format).toBe("7z");
    expect(env.data.archive_password).toBe("malware");
    expect(env.data.host_path).toBe(`${hostDir}/payload.exe.7z`);

    // Verify 7z command was called
    const archiveCall = exec.mock.calls[2];
    expect(archiveCall[0][0]).toBe("7z");
    expect(archiveCall[0]).toContain("-pmalware");
  });

  it("returns error when archive creation fails", async () => {
    const deps = sandboxedDeps();
    const exec = vi.mocked(deps.connector.execute);

    exec
      .mockResolvedValueOnce(ok("1024"))                       // stat
      .mockResolvedValueOnce(ok("abc123  /output/file.bin"))   // sha256sum
      .mockResolvedValueOnce({ stdout: "", stderr: "zip not found", exitCode: 127 }); // zip fails

    const result = await handleDownloadFile(deps, {
      file_path: "file.bin",
      output_path: hostDir,
    });
    const env = parseEnvelope(result);
    expect(env.success).toBe(false);
    expect(env.error_code).toBe("ARCHIVE_FAILED");
  });

  it("cleans up temp archive even if transfer fails", async () => {
    const deps = sandboxedDeps();
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
      output_path: hostDir,
    });
    const env = parseEnvelope(result);
    expect(env.success).toBe(false);

    // Verify cleanup was attempted (rm -f call)
    const rmCall = exec.mock.calls[3];
    expect(rmCall[0][0]).toBe("rm");
    expect(rmCall[0][1]).toBe("-f");
  });

  it("rejects archive password with shell metacharacters", async () => {
    const deps = sandboxedDeps();
    // Store metadata with a malicious password containing shell metacharacters
    deps.sessionState.storeArchiveInfo("evil.zip", ["payload.exe"], "zip", "pass;rm -rf /");

    const exec = vi.mocked(deps.connector.execute);
    exec
      .mockResolvedValueOnce(ok("1024"))                       // stat
      .mockResolvedValueOnce(ok("abc123  /output/payload.exe")); // sha256sum

    const result = await handleDownloadFile(deps, {
      file_path: "payload.exe",
      output_path: hostDir,
    });
    const env = parseEnvelope(result);
    expect(env.success).toBe(false);
    expect(env.error_code).toBe("INVALID_PASSWORD");
  });

  it("rejects invalid output_path", async () => {
    const deps = sandboxedDeps();

    const result = await handleDownloadFile(deps, {
      file_path: "file.bin",
      output_path: "relative/path",
    });
    const env = parseEnvelope(result);
    expect(env.success).toBe(false);
    expect(env.error_code).toBe("INVALID_PATH");
  });

  it("handles sha256sum failure gracefully (returns 'unknown')", async () => {
    const deps = sandboxedDeps();
    const exec = vi.mocked(deps.connector.execute);

    exec
      .mockResolvedValueOnce(ok("100"))       // stat
      .mockResolvedValueOnce(ok(""))           // sha256sum empty output
      .mockResolvedValueOnce(ok(""))           // zip
      .mockResolvedValueOnce(ok(""));          // rm cleanup
    vi.mocked(deps.connector.readFileToPath).mockResolvedValueOnce(undefined);

    const result = await handleDownloadFile(deps, {
      file_path: "file.bin",
      output_path: hostDir,
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

    // No ingest root in play without the sandbox: any existing directory works.
    const result = await handleDownloadFile(deps, {
      file_path: "../../etc/passwd",
      output_path: "/tmp/downloads",
    });
    const env = parseEnvelope(result);
    expect(env.success).toBe(true);
  });

  it("rejects files exceeding 200MB", async () => {
    const deps = sandboxedDeps();
    const exec = vi.mocked(deps.connector.execute);

    const bigSize = String(201 * 1024 * 1024);
    exec
      .mockResolvedValueOnce(ok(bigSize))
      .mockResolvedValueOnce(ok("abc  file"));

    const result = await handleDownloadFile(deps, {
      file_path: "file.bin",
      output_path: hostDir,
    });
    const env = parseEnvelope(result);
    expect(env.success).toBe(false);
    expect(env.error_code).toBe("FILE_TOO_LARGE");
  });

  it("rejects non-existent output directory", async () => {
    const { existsSync } = await import("fs");
    vi.mocked(existsSync).mockReturnValueOnce(false);

    const deps = sandboxedDeps();
    const result = await handleDownloadFile(deps, {
      file_path: "file.bin",
      output_path: "/nonexistent/dir",
    });
    const env = parseEnvelope(result);
    expect(env.success).toBe(false);
    expect(env.error_code).toBe("INVALID_PATH");
  });

  it("uses basename when file_path contains subdirectory", async () => {
    const deps = sandboxedDeps();
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
      output_path: hostDir,
    });
    const env = parseEnvelope(result);
    expect(env.success).toBe(true);
    expect(env.data.host_path).toBe(`${hostDir}/result.json.zip`);
  });

  it("wraps connector errors", async () => {
    const deps = sandboxedDeps();
    vi.mocked(deps.connector.execute).mockRejectedValue(new Error("connection lost"));

    const result = await handleDownloadFile(deps, {
      file_path: "file.bin",
      output_path: hostDir,
    });
    const env = parseEnvelope(result);
    expect(env.success).toBe(false);
    expect(result.isError).toBe(true);
  });
});

// The host-side destination is the one place download_file writes outside the
// container/VM isolation boundary (docker/ssh mode). These pin the checks on it.
describe("handleDownloadFile — host destination checks", () => {
  it("with --sandbox, rejects an output_path outside the ingest root before touching REMnux", async () => {
    const outside = makeTempDir("download-file-outside-");
    const deps = sandboxedDeps();

    const result = await handleDownloadFile(deps, {
      file_path: "file.bin",
      output_path: outside,
      archive: false,
    });
    const env = parseEnvelope(result);
    expect(env.success).toBe(false);
    expect(env.error_code).toBe("INVALID_PATH");
    expect(deps.connector.execute).not.toHaveBeenCalled();
    expect(deps.connector.readFileToPath).not.toHaveBeenCalled();
  });

  it("with --sandbox, accepts a subdirectory of the ingest root (control)", async () => {
    const inside = join(hostDir, "inside");
    mkdirSync(inside);
    const deps = sandboxedDeps();
    vi.mocked(deps.connector.execute)
      .mockResolvedValueOnce(ok("12"))
      .mockResolvedValueOnce(ok("abc  /output/file.bin"));
    vi.mocked(deps.connector.readFileToPath).mockResolvedValueOnce(undefined);

    const result = await handleDownloadFile(deps, {
      file_path: "file.bin",
      output_path: inside,
      archive: false,
    });
    const env = parseEnvelope(result);
    expect(env.success).toBe(true);
    expect(env.data.host_path).toBe(join(inside, "file.bin"));
  });

  it("refuses to write through a symlink at the destination, even with overwrite: true", async () => {
    const target = join(makeTempDir("download-file-target-"), "target.txt");
    writeFileSync(target, "keep me");
    symlinkSync(target, join(hostDir, "linked.bin"));
    const deps = sandboxedDeps();
    vi.mocked(deps.connector.execute)
      .mockResolvedValueOnce(ok("12"))
      .mockResolvedValueOnce(ok("abc  /output/linked.bin"));

    const result = await handleDownloadFile(deps, {
      file_path: "linked.bin",
      output_path: hostDir,
      archive: false,
      overwrite: true,
    });
    const env = parseEnvelope(result);
    expect(env.success).toBe(false);
    expect(env.error_code).toBe("INVALID_PATH");
    expect(deps.connector.readFileToPath).not.toHaveBeenCalled();
  });

  it("refuses to replace an existing raw destination unless overwrite: true", async () => {
    writeFileSync(join(hostDir, "existing.bin"), "old");
    const deps = sandboxedDeps();
    vi.mocked(deps.connector.execute)
      .mockResolvedValue(ok("12"));

    const refused = parseEnvelope(await handleDownloadFile(deps, {
      file_path: "existing.bin",
      output_path: hostDir,
      archive: false,
    }));
    expect(refused.success).toBe(false);
    expect(refused.error_code).toBe("FILE_EXISTS");
    expect(deps.connector.readFileToPath).not.toHaveBeenCalled();

    vi.mocked(deps.connector.readFileToPath).mockResolvedValueOnce(undefined);
    const replaced = parseEnvelope(await handleDownloadFile(deps, {
      file_path: "existing.bin",
      output_path: hostDir,
      archive: false,
      overwrite: true,
    }));
    expect(replaced.success).toBe(true);
    expect(deps.connector.readFileToPath).toHaveBeenCalledWith("/output/existing.bin", join(hostDir, "existing.bin"));
  });

  it("checks the archived destination (<name>.zip) before creating the archive in REMnux", async () => {
    writeFileSync(join(hostDir, "report.txt.zip"), "old archive");
    const deps = sandboxedDeps();
    const exec = vi.mocked(deps.connector.execute);
    exec
      .mockResolvedValueOnce(ok("12"))                        // stat
      .mockResolvedValueOnce(ok("abc  /output/report.txt"));  // sha256sum

    const env = parseEnvelope(await handleDownloadFile(deps, {
      file_path: "report.txt",
      output_path: hostDir,
    }));
    expect(env.success).toBe(false);
    expect(env.error_code).toBe("FILE_EXISTS");
    // stat and sha256sum ran; no archive command and no cleanup followed
    expect(exec).toHaveBeenCalledTimes(2);
    expect(deps.connector.readFileToPath).not.toHaveBeenCalled();
  });
});

// The container-side source must be a regular file: docker cp copies a whole
// directory tree and lands a symlink as a symlink on the host.
describe("handleDownloadFile — source type", () => {
  it.each([
    ["4096 directory", "directory"],
    ["80 symbolic link", "symbolic link"],
    ["0 fifo", "fifo"],
  ])("refuses a source that stat reports as %s", async (statLine, kind) => {
    const deps = sandboxedDeps();
    const exec = vi.mocked(deps.connector.execute);
    exec
      .mockResolvedValueOnce(ok(statLine))                       // stat -c "%s %F"
      .mockResolvedValueOnce(ok("abc  /output/thing"));          // sha256sum

    const env = parseEnvelope(await handleDownloadFile(deps, {
      file_path: "thing",
      output_path: hostDir,
      archive: false,
    }));
    expect(env.success).toBe(false);
    expect(env.error_code).toBe("INVALID_PATH");
    expect(env.error).toContain(kind);
    expect(exec).toHaveBeenCalledTimes(2);
    expect(deps.connector.readFileToPath).not.toHaveBeenCalled();
  });

  it("accepts a regular file and a regular empty file (control)", async () => {
    for (const statLine of ["12 regular file", "0 regular empty file"]) {
      const deps = sandboxedDeps();
      vi.mocked(deps.connector.execute)
        .mockResolvedValueOnce(ok(statLine))
        .mockResolvedValueOnce(ok("abc  /output/plain.txt"));
      vi.mocked(deps.connector.readFileToPath).mockResolvedValueOnce(undefined);
      const env = parseEnvelope(await handleDownloadFile(deps, {
        file_path: `plain-${statLine.split(" ")[0]}.txt`,
        output_path: hostDir,
        archive: false,
      }));
      expect(env.success).toBe(true);
      expect(env.data.size_bytes).toBe(parseInt(statLine, 10));
    }
  });

  it("asks stat for size and type in one call", async () => {
    const deps = sandboxedDeps();
    const exec = vi.mocked(deps.connector.execute);
    exec.mockResolvedValueOnce(ok("5 regular file")).mockResolvedValueOnce(ok("abc  x"));
    vi.mocked(deps.connector.readFileToPath).mockResolvedValueOnce(undefined);
    await handleDownloadFile(deps, { file_path: "x.txt", output_path: hostDir, archive: false });
    expect(exec.mock.calls[0][0]).toEqual(["stat", "-c", "%s %F", "/output/x.txt"]);
  });
});
