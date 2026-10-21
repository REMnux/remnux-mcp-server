import { describe, it, expect, vi } from "vitest";
import {
  getExtractionCommand,
  findEscapingSymlinks,
  extractArchive,
  isOutputDirInside,
  type ExtractedSymlink,
} from "../archive-extractor.js";
import type { Connector } from "../connectors/index.js";

describe("getExtractionCommand — password option injection", () => {
  it("rejects a password that starts with '-' (zip -P option injection)", () => {
    expect(() =>
      getExtractionCommand("zip", "/samples/a.zip", "/out", "--help")
    ).toThrow(/option injection/);
  });

  it("rejects a leading-dash password for 7z and rar too (consistency)", () => {
    expect(() =>
      getExtractionCommand("7z", "/samples/a.7z", "/out", "-x")
    ).toThrow(/option injection/);
    expect(() =>
      getExtractionCommand("rar", "/samples/a.rar", "/out", "-x")
    ).toThrow(/option injection/);
  });

  it("still rejects shell metacharacters in the password", () => {
    expect(() =>
      getExtractionCommand("zip", "/samples/a.zip", "/out", "a;b")
    ).toThrow(/invalid characters/);
  });

  it("passes a normal password through as a standalone argv token for zip", () => {
    const cmd = getExtractionCommand("zip", "/samples/a.zip", "/out", "infected");
    expect(cmd).toEqual([
      "unzip",
      "-o",
      "-P",
      "infected",
      "-d",
      "/out",
      "/samples/a.zip",
    ]);
  });

  it("glues the password for 7z and builds the expected command", () => {
    const cmd = getExtractionCommand("7z", "/samples/a.7z", "/out", "infected");
    expect(cmd).toContain("-pinfected");
  });

  it("builds a passwordless command unchanged", () => {
    const cmd = getExtractionCommand("zip", "/samples/a.zip", "/out");
    expect(cmd).toEqual(["unzip", "-o", "-d", "/out", "/samples/a.zip"]);
  });
});

describe("findEscapingSymlinks — zip-slip via symlink indirection", () => {
  const outputDir = "/home/remnux/files/output/job";

  it("flags a symlink with an absolute target outside outputDir", () => {
    const links: ExtractedSymlink[] = [{ name: "link", target: "/home/remnux" }];
    expect(findEscapingSymlinks(links, outputDir)).toEqual(["link"]);
  });

  it("flags a symlink with a relative target that escapes outputDir", () => {
    const links: ExtractedSymlink[] = [{ name: "link", target: "../../../etc" }];
    expect(findEscapingSymlinks(links, outputDir)).toEqual(["link"]);
  });

  it("flags a nested symlink whose relative target escapes its own directory", () => {
    const links: ExtractedSymlink[] = [
      { name: "sub/link", target: "../../../../tmp" },
    ];
    expect(findEscapingSymlinks(links, outputDir)).toEqual(["sub/link"]);
  });

  it("treats an unresolved target (portable fallback) as an escape — fail closed", () => {
    const links: ExtractedSymlink[] = [{ name: "link", target: "" }];
    expect(findEscapingSymlinks(links, outputDir)).toEqual(["link"]);
  });

  it("allows an internal symlink whose target stays within outputDir", () => {
    const links: ExtractedSymlink[] = [
      { name: "a", target: "./b" },
      { name: "deep/c", target: "../d" },
      { name: "abs", target: `${outputDir}/inside` },
    ];
    expect(findEscapingSymlinks(links, outputDir)).toEqual([]);
  });

  it("returns no escapes for an empty symlink list", () => {
    expect(findEscapingSymlinks([], outputDir)).toEqual([]);
  });
});

describe("extractArchive — output directory stays inside samplesDir", () => {
  it("isOutputDirInside accepts a child and a nested child, rejects self, parent, sibling, and absolute escapes", () => {
    expect(isOutputDirInside("/samples/case1", "/samples")).toBe(true);
    expect(isOutputDirInside("/samples/case1/stage2", "/samples")).toBe(true);
    expect(isOutputDirInside("/samples/..case", "/samples")).toBe(true); // a name, not a parent
    expect(isOutputDirInside("/samples", "/samples")).toBe(false);
    expect(isOutputDirInside("/samples/.", "/samples")).toBe(false);
    expect(isOutputDirInside("/samples/..", "/samples")).toBe(false);
    expect(isOutputDirInside("/samples/../probe", "/samples")).toBe(false);
    expect(isOutputDirInside("/samples-evil", "/samples")).toBe(false);
    expect(isOutputDirInside("/", "/samples")).toBe(false);
  });

  // The handler validates output_subdir only with --sandbox on; this check in
  // extractArchive holds regardless, because the zip-slip cleanup runs rm -rf on
  // the output directory. No connector call may happen before the refusal.
  it("refuses an output_subdir that escapes samplesDir before any command runs", async () => {
    const execute = vi.fn();
    const connector = { execute } as unknown as Connector;
    // path.join treats a leading "/" as a relative segment ("/samples/abs"), so an
    // absolute-looking subdir is contained, not an escape; only ".." and "." escape.
    for (const subdir of ["..", "../../probe", ".", "a/../.."]) {
      execute.mockClear();
      const result = await extractArchive(connector, "/samples/a.zip", "/samples", undefined, subdir);
      expect(result.success).toBe(false);
      expect(result.error).toContain("inside the samples directory");
      expect(execute).not.toHaveBeenCalled();
    }
  });

  it("allows a derived output name that merely starts with '..' (archive named '..case.zip')", async () => {
    const execute = vi.fn().mockResolvedValue({ stdout: "", stderr: "", exitCode: 0 });
    const connector = { execute } as unknown as Connector;
    await extractArchive(connector, "/samples/..case.zip", "/samples");
    expect(execute.mock.calls[0][0]).toEqual(["mkdir", "-p", "/samples/..case"]);
  });

  it("refuses a derived output name of '..' (archive named '...zip')", async () => {
    const execute = vi.fn();
    const connector = { execute } as unknown as Connector;
    const result = await extractArchive(connector, "/samples/...zip", "/samples");
    expect(result.success).toBe(false);
    expect(execute).not.toHaveBeenCalled();
  });

  it("still allows a nested subdirectory name (control)", async () => {
    // mkdir succeeds, listing reports nothing, extraction fails: we only care
    // that the containment check let the call proceed to the connector.
    const execute = vi.fn().mockResolvedValue({ stdout: "", stderr: "", exitCode: 0 });
    const connector = { execute } as unknown as Connector;
    await extractArchive(connector, "/samples/a.zip", "/samples", undefined, "case1/stage2");
    expect(execute).toHaveBeenCalled();
    expect(execute.mock.calls[0][0]).toEqual(["mkdir", "-p", "/samples/case1/stage2"]);
  });
});
