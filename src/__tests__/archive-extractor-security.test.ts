import { describe, it, expect } from "vitest";
import {
  getExtractionCommand,
  findEscapingSymlinks,
  type ExtractedSymlink,
} from "../archive-extractor.js";

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
