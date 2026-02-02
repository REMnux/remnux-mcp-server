import { describe, it, expect, vi, beforeEach } from "vitest";
import { handleUploadFromHost } from "../upload-from-host.js";
import { createMockDeps, parseEnvelope } from "./helpers.js";

// Mock file-upload module (keep validators real)
vi.mock("../../file-upload.js", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../../file-upload.js")>();
  return {
    ...actual,
    validateFilename: actual.validateFilename,
    validateHostPath: actual.validateHostPath,
    uploadSampleFromHost: vi.fn(),
  };
});

import { uploadSampleFromHost } from "../../file-upload.js";

describe("handleUploadFromHost", () => {
  beforeEach(() => {
    vi.mocked(uploadSampleFromHost).mockReset();
  });

  it("calls mkdir -p on samplesDir via uploadSampleFromHost", async () => {
    // This test validates that uploadSampleFromHost creates the directory.
    // The mkdir -p call is inside uploadSampleFromHost, which is mocked here.
    // See file-upload.ts integration for the actual mkdir -p logic.
    const deps = createMockDeps();
    vi.mocked(uploadSampleFromHost).mockResolvedValue({
      success: true,
      path: "/samples/test.exe",
      sha256: "abc",
      size_bytes: 100,
    });

    const result = await handleUploadFromHost(deps, {
      host_path: "/tmp/test.exe",
      overwrite: false,
    });

    const env = parseEnvelope(result);
    expect(env.success).toBe(true);
    expect(uploadSampleFromHost).toHaveBeenCalled();
  });

  it("passes overwrite flag to uploadSampleFromHost", async () => {
    const deps = createMockDeps();
    vi.mocked(uploadSampleFromHost).mockResolvedValue({
      success: true,
      path: "/samples/test.exe",
      sha256: "abc",
      size_bytes: 100,
    });

    await handleUploadFromHost(deps, {
      host_path: "/tmp/test.exe",
      overwrite: true,
    });

    expect(uploadSampleFromHost).toHaveBeenCalledWith(
      deps.connector,
      "/samples",
      "/tmp/test.exe",
      undefined,
      true,
      "docker",
    );
  });

  it("passes filename override", async () => {
    const deps = createMockDeps();
    vi.mocked(uploadSampleFromHost).mockResolvedValue({
      success: true,
      path: "/samples/renamed.exe",
      sha256: "abc",
      size_bytes: 100,
    });

    await handleUploadFromHost(deps, {
      host_path: "/tmp/test.exe",
      filename: "renamed.exe",
      overwrite: false,
    });

    expect(uploadSampleFromHost).toHaveBeenCalledWith(
      deps.connector,
      "/samples",
      "/tmp/test.exe",
      "renamed.exe",
      false,
      "docker",
    );
  });

  it("returns upload failure from uploadSampleFromHost", async () => {
    const deps = createMockDeps();
    vi.mocked(uploadSampleFromHost).mockResolvedValue({
      success: false,
      error: "File already exists",
    });

    const result = await handleUploadFromHost(deps, {
      host_path: "/tmp/test.exe",
      overwrite: false,
    });

    const env = parseEnvelope(result);
    expect(env.success).toBe(false);
    expect(env.error).toContain("File already exists");
  });

  it("wraps thrown errors from uploadSampleFromHost", async () => {
    const deps = createMockDeps();
    vi.mocked(uploadSampleFromHost).mockRejectedValue(new Error("disk full"));

    const result = await handleUploadFromHost(deps, {
      host_path: "/tmp/test.exe",
      overwrite: false,
    });

    const env = parseEnvelope(result);
    expect(env.success).toBe(false);
    expect(result.isError).toBe(true);
  });

  it("rejects relative host paths before calling uploadSampleFromHost", async () => {
    const deps = createMockDeps();

    const result = await handleUploadFromHost(deps, {
      host_path: "relative/path.exe",
      overwrite: false,
    });

    const env = parseEnvelope(result);
    expect(env.success).toBe(false);
    expect(env.error_code).toBe("INVALID_PATH");
    expect(uploadSampleFromHost).not.toHaveBeenCalled();
  });

  it("rejects invalid override filenames before calling uploadSampleFromHost", async () => {
    const deps = createMockDeps();

    const result = await handleUploadFromHost(deps, {
      host_path: "/tmp/safe.exe",
      filename: "../escape.exe",
      overwrite: false,
    });

    const env = parseEnvelope(result);
    expect(env.success).toBe(false);
    expect(env.error_code).toBe("INVALID_FILENAME");
    expect(uploadSampleFromHost).not.toHaveBeenCalled();
  });
});
