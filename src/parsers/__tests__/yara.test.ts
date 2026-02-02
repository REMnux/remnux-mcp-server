import { describe, it, expect } from "vitest";
import { parseYaraOutput } from "../yara.js";

describe("parseYaraOutput", () => {
  it("deduplicates packer family variants", () => {
    const output = [
      "PECompact_v1 /samples/test.exe",
      "PECompact_v2 /samples/test.exe",
      "PECompact_v20 /samples/test.exe",
      "PECompact_v3 /samples/test.exe",
    ].join("\n");
    const result = parseYaraOutput(output);
    expect(result.parsed).toBe(true);
    expect(result.findings).toHaveLength(1);
    expect(result.findings[0].description).toContain("PECompact");
    expect(result.findings[0].description).toContain("4 rule variants");
    expect(result.metadata.total_rules_matched).toBe(4);
    expect(result.metadata.deduplicated_findings).toBe(1);
  });

  it("keeps non-packer rules individual", () => {
    const output = [
      "suspicious_strings /samples/test.exe",
      "known_malware_family /samples/test.exe",
    ].join("\n");
    const result = parseYaraOutput(output);
    expect(result.parsed).toBe(true);
    expect(result.findings).toHaveLength(2);
    expect(result.findings[0].category).toBe("yara-match");
  });

  it("mixes packer dedup with individual rules", () => {
    const output = [
      "UPX_v3 /samples/test.exe",
      "UPX_v4 /samples/test.exe",
      "suspicious_strings /samples/test.exe",
    ].join("\n");
    const result = parseYaraOutput(output);
    expect(result.findings).toHaveLength(2); // 1 UPX + 1 individual
  });

  it("returns unparsed for empty output", () => {
    const result = parseYaraOutput("");
    expect(result.parsed).toBe(false);
  });
});
