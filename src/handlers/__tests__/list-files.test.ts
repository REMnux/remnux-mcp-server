import { describe, it, expect, vi } from "vitest";
import { handleListFiles } from "../list-files.js";
import { createMockDeps, ok, fail, parseEnvelope } from "./helpers.js";

describe("handleListFiles", () => {
  it("parses symlink names stripping ' -> ' target", async () => {
    const deps = createMockDeps();
    vi.mocked(deps.connector.execute).mockResolvedValue(
      ok(
        "total 4\n" +
        "lrwxrwxrwx 1 root root 20 Jan  1 12:00 mylink -> /outside/sandbox/target\n"
      )
    );

    const result = await handleListFiles(deps, { directory: "samples" });
    const env = parseEnvelope(result);
    expect(env.data.entries).toHaveLength(1);
    expect(env.data.entries[0].name).toBe("mylink");
    expect(env.data.entries[0].type).toBe("symlink");
  });

  it("handles empty directory (only total line)", async () => {
    const deps = createMockDeps();
    vi.mocked(deps.connector.execute).mockResolvedValue(ok("total 0\n"));

    const result = await handleListFiles(deps, { directory: "samples" });
    const env = parseEnvelope(result);
    expect(env.data.entries).toHaveLength(0);
    expect(env.data.entry_count).toBe(0);
  });

  it("skips . and .. entries", async () => {
    const deps = createMockDeps();
    vi.mocked(deps.connector.execute).mockResolvedValue(
      ok(
        "total 8\n" +
        "drwxr-xr-x 2 root root 4096 Jan  1 12:00 .\n" +
        "drwxr-xr-x 3 root root 4096 Jan  1 12:00 ..\n" +
        "-rw-r--r-- 1 root root 1024 Jan  1 12:00 file.exe\n"
      )
    );

    const result = await handleListFiles(deps, { directory: "samples" });
    const env = parseEnvelope(result);
    expect(env.data.entries).toHaveLength(1);
    expect(env.data.entries[0].name).toBe("file.exe");
  });

  it("skips malformed lines that don't match ls pattern", async () => {
    const deps = createMockDeps();
    vi.mocked(deps.connector.execute).mockResolvedValue(
      ok(
        "total 4\n" +
        "garbage line here\n" +
        "-rw-r--r-- 1 root root 512 Jan  1 12:00 good.txt\n"
      )
    );

    const result = await handleListFiles(deps, { directory: "samples" });
    const env = parseEnvelope(result);
    expect(env.data.entries).toHaveLength(1);
    expect(env.data.entries[0].name).toBe("good.txt");
  });

  it("uses outputDir for 'output' directory argument", async () => {
    const deps = createMockDeps();
    vi.mocked(deps.connector.execute).mockResolvedValue(ok("total 0\n"));

    await handleListFiles(deps, { directory: "output" });

    expect(deps.connector.execute).toHaveBeenCalledWith(
      ["ls", "-la", "/output"],
      { timeout: 30000 }
    );
  });

  it("returns DIR_NOT_FOUND when directory does not exist", async () => {
    const deps = createMockDeps();
    vi.mocked(deps.connector.execute).mockResolvedValue(
      fail("ls: cannot access '/samples': No such file or directory", 2)
    );

    const result = await handleListFiles(deps, { directory: "samples" });
    const env = parseEnvelope(result);
    expect(env.success).toBe(false);
    expect(env.error_code).toBe("DIR_NOT_FOUND");
    expect(env.error).toContain("does not exist");
    expect(env.remediation).toContain("Upload a file first");
  });

  it("returns COMMAND_FAILED for non-directory ls errors", async () => {
    const deps = createMockDeps();
    vi.mocked(deps.connector.execute).mockResolvedValue(
      fail("ls: permission denied", 1)
    );

    const result = await handleListFiles(deps, { directory: "samples" });
    const env = parseEnvelope(result);
    expect(env.success).toBe(false);
    expect(env.error_code).toBe("COMMAND_FAILED");
  });

  it("wraps connector errors", async () => {
    const deps = createMockDeps();
    vi.mocked(deps.connector.execute).mockRejectedValue(new Error("not running"));

    const result = await handleListFiles(deps, { directory: "samples" });
    const env = parseEnvelope(result);
    expect(env.success).toBe(false);
    expect(result.isError).toBe(true);
  });
});
