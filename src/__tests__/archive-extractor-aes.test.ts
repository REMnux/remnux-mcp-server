import { describe, it, expect } from "vitest";
import {
  isUnsupportedZipEncryption,
  extractArchive,
} from "../archive-extractor.js";
import type { Connector, ExecResult } from "../connectors/index.js";

const ok = (stdout = "", stderr = "", exitCode = 0): ExecResult => ({
  stdout,
  stderr,
  exitCode,
});

describe("isUnsupportedZipEncryption", () => {
  it("detects the WinZip AES skip marker from unzip", () => {
    expect(
      isUnsupportedZipEncryption(
        ok("  skipping: payload.txt  need PK compat. v5.1 (can do v4.6)")
      )
    ).toBe(true);
  });

  it("detects an unsupported-compression-method message", () => {
    expect(
      isUnsupportedZipEncryption(ok("", "unsupported compression method", 1))
    ).toBe(true);
  });

  it("does not fire on a normal successful extraction", () => {
    expect(isUnsupportedZipEncryption(ok("extracting: payload.txt"))).toBe(false);
  });

  it("does not fire on a traditional wrong-password error", () => {
    expect(
      isUnsupportedZipEncryption(ok("", "incorrect password", 82))
    ).toBe(false);
  });
});

/**
 * Fake connector that routes by argv[0] so we can drive the AES fallback:
 * unzip reports the AES skip (exit 0, no files), 7z then extracts successfully.
 */
function makeConnector(behavior: {
  unzip: ExecResult;
  sevenZip: ExecResult;
  extractedFiles: string[];
}): { connector: Connector; calls: string[][] } {
  const calls: string[][] = [];
  const connector: Connector = {
    async execute(command: string[]): Promise<ExecResult> {
      calls.push(command);
      const tool = command[0];
      if (tool === "mkdir" || tool === "rm") return ok();
      if (tool === "zipinfo") return ok("payload.txt"); // pre-extraction listing
      if (tool === "unzip") return behavior.unzip;
      if (tool === "7z" && command[1] === "x") return behavior.sevenZip;
      if (tool === "7z" && command[1] === "l") return ok("");
      if (tool === "find") {
        // listExtractedFiles (-type f) vs listExtractedSymlinks (-type l)
        const isSymlink = command.includes("l") && command.includes("-type");
        const wantsFiles = command[command.indexOf("-type") + 1] === "f";
        if (wantsFiles && !isSymlink) {
          return ok(behavior.extractedFiles.join("\n"));
        }
        return ok(""); // no symlinks
      }
      return ok();
    },
    async executeShell() {
      return ok();
    },
    async writeFile() {},
    async writeFileFromPath() {},
    async readFileToPath() {},
    async disconnect() {},
  };
  return { connector, calls };
}

describe("extractArchive — WinZip AES .zip fallback to 7z", () => {
  it("falls back to 7z when unzip skips AES entries, and reports the files", async () => {
    const { connector, calls } = makeConnector({
      unzip: ok("  skipping: payload.txt  need PK compat. v5.1 (can do v4.6)"),
      sevenZip: ok("Everything is Ok"),
      extractedFiles: ["payload.txt"],
    });

    const result = await extractArchive(
      connector,
      "/samples/winzip-aes.zip",
      "/samples",
      "s3cret"
    );

    expect(result.success).toBe(true);
    expect(result.files).toEqual(["payload.txt"]);
    expect(result.password).toBe("s3cret");
    // The 7z fallback was actually invoked with the extract verb.
    expect(calls.some((c) => c[0] === "7z" && c[1] === "x")).toBe(true);
  });

  it("does not invoke the 7z fallback for a normal ZipCrypto zip that unzip handles", async () => {
    const { connector, calls } = makeConnector({
      unzip: ok("extracting: payload.txt"),
      sevenZip: ok("should not be called"),
      extractedFiles: ["payload.txt"],
    });

    const result = await extractArchive(
      connector,
      "/samples/zipcrypto.zip",
      "/samples",
      "infected"
    );

    expect(result.success).toBe(true);
    expect(result.files).toEqual(["payload.txt"]);
    expect(calls.some((c) => c[0] === "7z" && c[1] === "x")).toBe(false);
  });
});
