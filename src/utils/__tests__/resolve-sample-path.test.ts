import { describe, it, expect } from "vitest";
import { resolveSamplePath } from "../resolve-sample-path.js";

describe("resolveSamplePath", () => {
  const samplesDir = "/home/remnux/files/samples";

  it("resolves a simple filename", () => {
    const result = resolveSamplePath("test.exe", samplesDir, "docker");
    expect(result.filePath).toBe("/home/remnux/files/samples/test.exe");
    expect(result.normalizedFile).toBe("test.exe");
  });

  it("strips duplicate samples/ prefix", () => {
    const result = resolveSamplePath("samples/test.exe", samplesDir, "docker");
    expect(result.filePath).toBe("/home/remnux/files/samples/test.exe");
    expect(result.normalizedFile).toBe("test.exe");
  });

  it("preserves subdirectory that does not match basename", () => {
    const result = resolveSamplePath("subdir/test.exe", samplesDir, "docker");
    expect(result.filePath).toBe("/home/remnux/files/samples/subdir/test.exe");
    expect(result.normalizedFile).toBe("subdir/test.exe");
  });

  it("returns absolute path unchanged in local mode", () => {
    const result = resolveSamplePath("/tmp/evil.bin", samplesDir, "local");
    expect(result.filePath).toBe("/tmp/evil.bin");
    expect(result.normalizedFile).toBe("/tmp/evil.bin");
  });

  it("returns absolute path unchanged in docker mode (no samplesDir duplication)", () => {
    // Regression: an absolute path (e.g. extract_archive's `extracted_to`) must not be
    // re-rooted under samplesDir, which produced "/samples//home/.../sample" and a
    // confusing "file not found" in docker/ssh mode.
    const result = resolveSamplePath("/home/remnux/files/samples/sub/evil.bin", samplesDir, "docker");
    expect(result.filePath).toBe("/home/remnux/files/samples/sub/evil.bin");
    expect(result.normalizedFile).toBe("/home/remnux/files/samples/sub/evil.bin");
  });

  it("prepends samplesDir for relative path in local mode", () => {
    const result = resolveSamplePath("test.exe", samplesDir, "local");
    expect(result.filePath).toBe("/home/remnux/files/samples/test.exe");
    expect(result.normalizedFile).toBe("test.exe");
  });

  it("does not strip prefix when samplesDir basename differs", () => {
    const result = resolveSamplePath("samples/test.exe", "/data/evidence", "docker");
    expect(result.filePath).toBe("/data/evidence/samples/test.exe");
    expect(result.normalizedFile).toBe("samples/test.exe");
  });
});
