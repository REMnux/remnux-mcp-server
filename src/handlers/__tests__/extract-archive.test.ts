import { describe, it, expect, vi, beforeEach } from "vitest";
import { handleExtractArchive } from "../extract-archive.js";
import { createMockDeps, parseEnvelope } from "./helpers.js";

// Mock archive-extractor module
vi.mock("../../archive-extractor.js", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../../archive-extractor.js")>();
  return {
    ...actual,
    detectArchiveType: actual.detectArchiveType,
    extractArchive: vi.fn(),
  };
});

import { extractArchive } from "../../archive-extractor.js";

describe("handleExtractArchive", () => {
  beforeEach(() => {
    vi.mocked(extractArchive).mockReset();
  });

  it("rejects blank output_subdir", async () => {
    const deps = createMockDeps();

    const result = await handleExtractArchive(deps, {
      archive_file: "test.zip",
      output_subdir: "   ",
    });

    const env = parseEnvelope(result);
    expect(env.success).toBe(false);
    expect(env.error_code).toBe("INVALID_SUBDIR");
  });

  it("rejects backtick in output_subdir", async () => {
    const deps = createMockDeps();

    const result = await handleExtractArchive(deps, {
      archive_file: "test.zip",
      output_subdir: "dir`whoami`",
    });

    const env = parseEnvelope(result);
    expect(env.success).toBe(false);
    expect(env.error_code).toBe("INVALID_SUBDIR");
  });

  it("rejects newline in output_subdir", async () => {
    const deps = createMockDeps();

    const result = await handleExtractArchive(deps, {
      archive_file: "test.zip",
      output_subdir: "dir\nname",
    });

    const env = parseEnvelope(result);
    expect(env.success).toBe(false);
    expect(env.error_code).toBe("INVALID_SUBDIR");
  });

  it("rejects path separators in output_subdir", async () => {
    const deps = createMockDeps();

    const result = await handleExtractArchive(deps, {
      archive_file: "test.zip",
      output_subdir: "../escape",
    });

    const env = parseEnvelope(result);
    expect(env.success).toBe(false);
    expect(env.error_code).toBe("INVALID_SUBDIR");
  });

  it("returns extraction failure from extractArchive", async () => {
    const deps = createMockDeps();
    vi.mocked(extractArchive).mockResolvedValue({
      success: false,
      error: "Corrupted archive",
      outputDir: "",
      files: [],
    });

    const result = await handleExtractArchive(deps, {
      archive_file: "bad.zip",
    });

    const env = parseEnvelope(result);
    expect(env.success).toBe(false);
    expect(env.error).toContain("Corrupted archive");
  });

  it("wraps thrown errors from extractArchive", async () => {
    const deps = createMockDeps();
    vi.mocked(extractArchive).mockRejectedValue(new Error("unexpected"));

    const result = await handleExtractArchive(deps, {
      archive_file: "test.zip",
    });

    const env = parseEnvelope(result);
    expect(env.success).toBe(false);
    expect(result.isError).toBe(true);
  });

  it("rejects unsupported archive format", async () => {
    const deps = createMockDeps();

    const result = await handleExtractArchive(deps, {
      archive_file: "test.tar.gz",
    });

    const env = parseEnvelope(result);
    expect(env.success).toBe(false);
    expect(env.error_code).toBe("UNSUPPORTED_FORMAT");
  });

  it("skips subdir validation when noSandbox is true", async () => {
    const deps = createMockDeps({ noSandbox: true });
    vi.mocked(extractArchive).mockResolvedValue({
      success: true,
      outputDir: "/samples/test",
      files: ["a.txt"],
    });

    // Backtick would be rejected with sandbox, but allowed without
    const result = await handleExtractArchive(deps, {
      archive_file: "test.zip",
      output_subdir: "dir`name`",
    });

    const env = parseEnvelope(result);
    expect(env.success).toBe(true);
  });
});
