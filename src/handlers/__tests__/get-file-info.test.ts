import { describe, it, expect, vi } from "vitest";
import { handleGetFileInfo } from "../get-file-info.js";
import { createMockDeps, ok, parseEnvelope } from "./helpers.js";

describe("handleGetFileInfo", () => {
  it("falls back to wc -c when stat fails", async () => {
    const deps = createMockDeps();
    const exec = vi.mocked(deps.connector.execute);

    exec
      .mockResolvedValueOnce(ok("sample.exe: PE32 executable"))  // file
      .mockResolvedValueOnce(ok("abc123  /samples/sample.exe"))  // sha256sum
      .mockResolvedValueOnce(ok("def456  /samples/sample.exe"))  // md5sum
      .mockResolvedValueOnce(ok("aaa111  /samples/sample.exe"))  // sha1sum
      .mockRejectedValueOnce(new Error("stat failed"))           // stat throws
      .mockResolvedValueOnce(ok("1024 /samples/sample.exe"));    // wc -c fallback

    const result = await handleGetFileInfo(deps, { file: "sample.exe" });
    const env = parseEnvelope(result);
    expect(env.success).toBe(true);
    expect(env.data.size_bytes).toBe(1024);
    // Verify wc -c was called
    expect(exec).toHaveBeenCalledWith(["wc", "-c", "/samples/sample.exe"], { timeout: 30000 });
  });

  it("falls back to wc -c when stat returns non-zero exit", async () => {
    const deps = createMockDeps();
    const exec = vi.mocked(deps.connector.execute);

    exec
      .mockResolvedValueOnce(ok("sample.exe: data"))             // file
      .mockResolvedValueOnce(ok("abc123  /samples/sample.exe"))  // sha256sum
      .mockResolvedValueOnce(ok("def456  /samples/sample.exe"))  // md5sum
      .mockResolvedValueOnce(ok("aaa111  /samples/sample.exe"))  // sha1sum
      .mockResolvedValueOnce({ stdout: "", stderr: "error", exitCode: 1 }) // stat non-zero
      .mockResolvedValueOnce(ok("2048 /samples/sample.exe"));    // wc -c

    const result = await handleGetFileInfo(deps, { file: "sample.exe" });
    const env = parseEnvelope(result);
    expect(env.data.size_bytes).toBe(2048);
  });

  it("returns error when all commands fail (no file type, no hashes)", async () => {
    const deps = createMockDeps();
    const exec = vi.mocked(deps.connector.execute);

    // All commands throw
    exec.mockRejectedValue(new Error("command failed"));

    const result = await handleGetFileInfo(deps, { file: "missing.exe" });
    const env = parseEnvelope(result);
    expect(env.success).toBe(false);
    expect(env.error_code).toBe("EMPTY_OUTPUT");
  });

  it("skips path validation when noSandbox is true", async () => {
    const deps = createMockDeps({ noSandbox: true });
    const exec = vi.mocked(deps.connector.execute);

    exec
      .mockResolvedValueOnce(ok("data"))    // file
      .mockResolvedValueOnce(ok("abc 1"))   // sha256
      .mockResolvedValueOnce(ok("def 1"))   // md5
      .mockResolvedValueOnce(ok("aaa 1"))   // sha1
      .mockResolvedValueOnce(ok("100"));    // stat

    const result = await handleGetFileInfo(deps, { file: "../../etc/passwd" });
    const env = parseEnvelope(result);
    expect(env.success).toBe(true);
  });

  it("omits size_bytes when both stat and wc -c fail", async () => {
    const deps = createMockDeps();
    const exec = vi.mocked(deps.connector.execute);

    exec
      .mockResolvedValueOnce(ok("sample: data"))                 // file
      .mockResolvedValueOnce(ok("abc123  file"))                 // sha256
      .mockResolvedValueOnce(ok("def456  file"))                 // md5
      .mockResolvedValueOnce(ok("aaa111  file"))                 // sha1
      .mockRejectedValueOnce(new Error("stat failed"))           // stat
      .mockRejectedValueOnce(new Error("wc failed"));            // wc -c

    const result = await handleGetFileInfo(deps, { file: "sample" });
    const env = parseEnvelope(result);
    expect(env.success).toBe(true);
    expect(env.data.size_bytes).toBeUndefined();
  });
});
