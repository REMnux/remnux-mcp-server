/**
 * capa exits 14 (E_FILE_LIMITATION) only without -j/-v/-vv. analyze_file runs `capa -j`,
 * which exits 0 and lists the limitation rule in its JSON as if it were a capability.
 * The rule names and namespaces below are capa-rules' own.
 */

import { describe, it, expect, vi } from "vitest";
import { handleAnalyzeFile } from "../analyze-file.js";
import { createMockDeps, ok, parseEnvelope } from "./helpers.js";

const ADDR = { type: "absolute", value: 0x401000 };
/** A matched rule whose match tree holds one api feature, as capa inlines sub-rules. */
function matched(namespace: string, attack: Array<{ technique: string; id: string }> = []) {
  const node = {
    success: true,
    node: { type: "statement", statement: { type: "and" } },
    children: [{ success: true, node: { type: "feature", feature: { type: "api" } }, children: [], locations: [] }],
    locations: [],
  };
  return { meta: { namespace, attack }, matches: [[ADDR, node]] };
}

function capaJson(rules: Record<string, ReturnType<typeof matched>>) {
  return JSON.stringify({ meta: { analysis: { format: "pe" } }, rules });
}

async function analyze(capaStdout: string) {
  const deps = createMockDeps();
  vi.mocked(deps.connector.execute).mockResolvedValue(
    ok("/samples/sample.exe: PE32 executable (GUI) Intel 80386, for MS Windows"),
  );
  vi.mocked(deps.connector.executeShell).mockImplementation(async (cmd: string) =>
    cmd.startsWith("capa") ? ok(capaStdout) : ok("clean"),
  );
  return parseEnvelope(await handleAnalyzeFile(deps, { file: "sample.exe", depth: "standard" }));
}

describe("analyze_file and capa file limitations", () => {
  const PACKED = capaJson({
    "packed with UPX": matched("anti-analysis/packer/upx", [{ technique: "Obfuscated Files or Information", id: "T1027.002" }]),
    "(internal) packer file limitation": matched("internal/limitation/static"),
  });

  it("raises the capa-file-limitation advisory from capa -j output (exit 0)", async () => {
    const env = await analyze(PACKED);
    const issues = (env.data.action_required ?? []).map((a: { issue: string }) => a.issue);
    expect(issues.some((i: string) => i.includes("file-limitation rules"))).toBe(true);
  });

  it("keeps the limitation out of capa_summary and capability_evidence", async () => {
    const env = await analyze(PACKED);
    const capa = env.data.tools_run.find((t: { name: string }) => t.name === "capa");
    const summary = capa.metadata.capa_summary;
    expect(summary.capability_count).toBe(1);
    expect(summary.top_capabilities).toEqual(["packed with UPX"]);
    expect(summary.attack_techniques).toEqual(["Obfuscated Files or Information"]);

    const ce = env.data.capability_evidence;
    expect(ce.behavior_capable).toEqual(["packed with UPX"]);
    expect(ce.artifact_only).toEqual([]);
  });

  it("counts in capa_summary only the rules the parser reads as capabilities", async () => {
    const malformed = JSON.stringify({
      rules: {
        "null rule": null,
        "bad attack": { meta: { namespace: "host-interaction/test", attack: "not-a-list" } },
        "mixed attack": { meta: { namespace: "host-interaction/test", attack: [null, { technique: "Process Injection" }] } },
      },
    });
    const env = await analyze(malformed);
    const capa = env.data.tools_run.find((t: { name: string }) => t.name === "capa");
    expect(capa.findings.map((f: { description: string }) => f.description)).toEqual(["bad attack", "mixed attack"]);
    expect(capa.metadata.capa_summary.capability_count).toBe(2);
    expect(capa.metadata.capa_summary.top_capabilities).toEqual(["bad attack", "mixed attack"]);
    expect(capa.metadata.capa_summary.attack_techniques).toEqual(["Process Injection"]);
  });

  it("raises no advisory for the dynamic .NET rule capa -j lists on ordinary .NET files", async () => {
    const env = await analyze(
      capaJson({
        "compiled to the .NET platform": matched("runtime/dotnet"),
        "(internal) .NET file limitation": matched("internal/limitation/dynamic"),
      }),
    );
    const issues = (env.data.action_required ?? []).map((a: { issue: string }) => a.issue);
    expect(issues.some((i: string) => i.includes("file-limitation rules"))).toBe(false);
    const capa = env.data.tools_run.find((t: { name: string }) => t.name === "capa");
    expect(capa.metadata.capa_summary.capability_count).toBe(2);
  });
});
