import { describe, it, expect } from "vitest";
import { extractIOCs } from "../extractor.js";

const HASH_TYPES = new Set(["md5", "sha1", "sha256", "sha512", "ssdeep"]);

const text = [
  "MD5     hash: 0f343b0931126a20f133d67c2b018a3b",
  "SHA-256 hash: 7d2a9e61c0b84f35a1e6d9c2b7f04e8a3c5d1b9e6f2a7c4d8e0b3f5a1c6d9e2b",
  "Fetched http://evil-updates.net/stage2.bin",
].join("\n");

const nonHash = (r: ReturnType<typeof extractIOCs>) =>
  r.iocs.filter((i) => !HASH_TYPES.has(i.type)).map((i) => `${i.type}:${i.value}`).sort();

describe("extractIOCs excludeTypes", () => {
  it("leaves out the listed types and keeps every other type", () => {
    const all = extractIOCs(text);
    const kept = extractIOCs(text, { excludeTypes: HASH_TYPES });

    // Control: without the option the hashes are reported.
    expect(all.iocs.some((i) => i.type === "md5")).toBe(true);
    expect(all.iocs.some((i) => i.type === "sha256")).toBe(true);

    expect(kept.iocs.some((i) => HASH_TYPES.has(i.type))).toBe(false);
    expect(kept.summary.by_type.md5).toBeUndefined();
    expect(kept.noise.some((i) => HASH_TYPES.has(i.type))).toBe(false);
    expect(nonHash(kept).length).toBeGreaterThan(0);
    expect(nonHash(kept)).toEqual(nonHash(all));
  });
});
