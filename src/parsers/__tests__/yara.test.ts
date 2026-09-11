import { describe, it, expect } from "vitest";
import { parseYaraOutput, parseYaraForgeOutput, extractYaraRuleMatches } from "../yara.js";

describe("extractYaraRuleMatches", () => {
  const T = "/home/remnux/files/samples/sample.exe";

  it("reads rule names from yara's match lines, tags and metadata included", () => {
    const out = `VENDORA_Win_Family ${T}\nns:VENDORB_Rule [tag1] [author="x y"] ${T}`;
    expect(extractYaraRuleMatches(out, T)).toEqual(["VENDORA_Win_Family", "ns:VENDORB_Rule"]);
  });

  it("does not read the server's no-output placeholder as a match", () => {
    expect(extractYaraRuleMatches("(no output)")).toEqual([]);
  });

  it("skips yara's warnings and errors", () => {
    const diag = `warning: rule "x" is slow\nerror scanning ${T}: could not open file`;
    expect(extractYaraRuleMatches(diag, T)).toEqual([]);
    expect(extractYaraRuleMatches(diag)).toEqual([]);
  });

  it("skips -s string-detail lines", () => {
    const out = `VENDORA_Win_Family ${T}\n0x1a2b:$s1: 4D 5A\n  0x10:$s2: 90`;
    expect(extractYaraRuleMatches(out, T)).toEqual(["VENDORA_Win_Family"]);
  });

  it("requires a line to name the scanned file when the caller knows it", () => {
    expect(extractYaraRuleMatches(`Scanning ${T} with 3 rulesets`, T)).toEqual([]);
    expect(extractYaraRuleMatches("VENDORA_Win_Family /other/file.exe", T)).toEqual([]);
  });

  it("accepts a scanned path that contains spaces", () => {
    const spaced = "/home/remnux/files/samples/invoice copy.exe";
    expect(extractYaraRuleMatches(`VENDORA_Win_Family ${spaced}`, spaced)).toEqual(["VENDORA_Win_Family"]);
  });

  it("matches a scanned path that ends in whitespace, whose echo the connector trimmed", () => {
    const trailing = "/home/remnux/files/samples/a.exe ";
    expect(extractYaraRuleMatches("VENDORA_Win_Family /home/remnux/files/samples/a.exe", trailing))
      .toEqual(["VENDORA_Win_Family"]);
  });

  it("needs a second token when the scanned file is not known", () => {
    expect(extractYaraRuleMatches("VENDORA_Win_Family")).toEqual([]);
  });
});

describe("parseYaraForgeOutput", () => {
  it("reports one finding per matched family rule, with the rule name preserved", () => {
    const r = parseYaraForgeOutput("VENDORA_Win_Family /s/x.exe\nVENDORA_Win_FamilyStrings /s/x.exe");
    expect(r.parsed).toBe(true);
    expect(r.findings.map((f) => f.evidence)).toEqual(["VENDORA_Win_Family", "VENDORA_Win_FamilyStrings"]);
    expect(r.findings[0].description).toBe("YARA family signature: VENDORA_Win_Family");
  });
});

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
