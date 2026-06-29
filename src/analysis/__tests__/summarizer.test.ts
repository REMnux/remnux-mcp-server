import { describe, it, expect } from "vitest";
import { summarizeCapabilityEvidence } from "../summarizer.js";
import type { Finding, EvidenceType } from "../../parsers/types.js";

/** Build a capa-style finding with optional evidence_types tags. */
function cap(description: string, ...evidence_types: EvidenceType[]): Finding {
  return evidence_types.length ? { description, evidence_types } : { description };
}
/** Wrap findings in a single capa ToolRun. */
function run(findings: Finding[]) {
  return [{ name: "capa", command: "capa -j x", output: "", exit_code: 0, findings }];
}

describe("summarizeCapabilityEvidence", () => {
  it("splits capability findings into behavior_capable vs artifact_only", () => {
    const ce = summarizeCapabilityEvidence(
      run([
        cap("connect to URL", "behavior"),
        cap("create shortcut via IShellLink", "artifact", "behavior"),
        cap("linked against CPP regex library", "artifact", "linking"),
        cap("reference HTTP User-Agent string", "artifact"),
      ]),
    );
    expect(ce).toBeDefined();
    // Anything whose match included code-level evidence is behavior_capable.
    expect(ce!.behavior_capable).toEqual(["connect to URL", "create shortcut via IShellLink"]);
    // Matches on data/imports/structure only stay artifact_only.
    expect(ce!.artifact_only).toEqual([
      "linked against CPP regex library",
      "reference HTTP User-Agent string",
    ]);
    expect(ce!.note.toLowerCase()).toContain("artifact");
  });

  it("returns undefined when no finding carries evidence_types", () => {
    expect(summarizeCapabilityEvidence(run([cap("some capability")]))).toBeUndefined();
    expect(summarizeCapabilityEvidence([])).toBeUndefined();
  });

  it("deduplicates capability names across tools", () => {
    const tools = [
      { name: "capa", command: "", output: "", exit_code: 0, findings: [cap("connect to URL", "behavior")] },
      { name: "capa-vv", command: "", output: "", exit_code: 0, findings: [cap("connect to URL", "behavior")] },
    ];
    expect(summarizeCapabilityEvidence(tools)!.behavior_capable).toEqual(["connect to URL"]);
  });

  it("caps very long lists with an overflow marker", () => {
    const findings = Array.from({ length: 65 }, (_, i) => cap(`cap ${i}`, "behavior"));
    const ce = summarizeCapabilityEvidence(run(findings));
    expect(ce!.behavior_capable).toHaveLength(61); // 60 names + overflow marker
    expect(ce!.behavior_capable[60]).toMatch(/and 5 more/);
  });

  it("ignores findings from tools that produced no tagged capabilities", () => {
    const tools = [
      { name: "diec", command: "", output: "", exit_code: 0, findings: [cap("packer: UPX")] },
      { name: "capa", command: "", output: "", exit_code: 0, findings: [cap("connect to URL", "behavior")] },
    ];
    const ce = summarizeCapabilityEvidence(tools);
    expect(ce!.behavior_capable).toEqual(["connect to URL"]);
    expect(ce!.artifact_only).toEqual([]);
  });
});
