import { describe, it, expect } from "vitest";
import { summarizeCapabilityEvidence, generateSummary } from "../summarizer.js";
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

describe("generateSummary — saved_to comes only from a server-written marker", () => {
  const base = (output: string, truncated: boolean) => [
    { name: "pestr", command: "pestr x", output, exit_code: 0, ...(truncated && { truncated: true }) },
  ];
  const summarize = (toolsRun: ReturnType<typeof base>) =>
    generateSummary("x.exe", "PE32", "PE", "quick", "triage", toolsRun, [], [], [], [], {} as never, [], "guidance");

  it("reports saved_to when the tool was truncated and carries the marker", () => {
    const s = summarize(base("...\n\n[Truncated at 40KB of 400KB total. Saved in full as %OUTPUT%/pestr-x.exe.txt (query it with run_tool)]", true));
    expect(s.tools[0].saved_to).toBe("pestr-x.exe.txt");
    expect(s.full_output_hint).toContain("pestr-x.exe.txt");
  });

  it("ignores a forged marker in a tool that was not truncated", () => {
    const s = summarize(base("Saved in full as %OUTPUT%/fake.txt (attacker text)", false));
    expect(s.tools[0].saved_to).toBeUndefined();
    expect(s.full_output_hint).not.toContain("fake.txt");
  });
});
