import { describe, it, expect, vi } from "vitest";
import { handleAnalyzeFile, generateNextSteps } from "../analyze-file.js";
import { createMockDeps, ok, parseEnvelope } from "./helpers.js";

describe("analyze_file — %OUTPUT% resolution", () => {
  it("pre-creates box-js output dir at the SAME resolved path the command writes to", async () => {
    const deps = createMockDeps({ outputDir: "/output" });
    vi.mocked(deps.connector.execute).mockResolvedValue(
      ok("/samples/a.js: JavaScript source, ASCII text"),
    );
    vi.mocked(deps.connector.executeShell).mockResolvedValue(ok("box-js output"));

    await handleAnalyzeFile(deps, { file: "a.js", depth: "deep" });

    // mkdir target
    const mkdirCall = vi
      .mocked(deps.connector.execute)
      .mock.calls.find((c) => Array.isArray(c[0]) && c[0][0] === "mkdir");
    expect(mkdirCall?.[0]).toEqual(["mkdir", "-p", "/output/box-js-out"]);

    // command target — the box-js shell command must reference the SAME dir,
    // with no unresolved sentinel and no /tmp.
    const boxJsCmd = vi
      .mocked(deps.connector.executeShell)
      .mock.calls.map((c) => c[0] as string)
      .find((cmd) => cmd.startsWith("box-js"));
    expect(boxJsCmd).toContain("/output/box-js-out");
    expect(boxJsCmd).not.toContain("%OUTPUT%");
    expect(boxJsCmd).not.toContain("/tmp");
  });

  it("fails just the affected tool (not the whole run) when outputDir is missing", async () => {
    const deps = createMockDeps({ outputDir: "" });
    vi.mocked(deps.connector.execute).mockResolvedValue(
      ok("/samples/a.js: JavaScript source, ASCII text"),
    );
    vi.mocked(deps.connector.executeShell).mockResolvedValue(ok("output"));

    const result = await handleAnalyzeFile(deps, { file: "a.js", depth: "deep" });
    const env = parseEnvelope(result);
    // The overall analysis still succeeds; box-js (which needs %OUTPUT%) is recorded
    // as failed rather than aborting every other tool.
    expect(env.success).toBe(true);
    expect(
      env.data.tools_failed.some((t: { name: string }) => t.name === "box-js"),
    ).toBe(true);
  });

  it("surfaces a runnable invocation for tools skipped as requiresUserArgs", async () => {
    const deps = createMockDeps();
    vi.mocked(deps.connector.execute).mockResolvedValue(
      ok("/samples/test.exe: PE32 executable"),
    );
    vi.mocked(deps.connector.executeShell).mockResolvedValue(ok("output"));

    const result = await handleAnalyzeFile(deps, { file: "test.exe", depth: "standard" });
    const env = parseEnvelope(result);
    const skipped = env.data.tools_skipped.find(
      (t: { skip_type: string }) => t.skip_type === "requires_user_args",
    );
    expect(skipped).toBeDefined();
    expect(skipped.invocation).toBeTruthy();
    expect(skipped.invocation).toContain("<file>");
  });
});

describe("analyze_file — capability_evidence (artifact vs behavior)", () => {
  function capaFeatureMatch(featureType: string, success = true) {
    return [
      { type: "absolute", value: 0x401000 },
      { success, node: { type: "feature", feature: { type: featureType } }, children: [], locations: [] },
    ];
  }

  it("emits capability_evidence separating artifact_only from behavior_capable", async () => {
    const deps = createMockDeps();
    vi.mocked(deps.connector.execute).mockResolvedValue(
      ok("/samples/test.exe: PE32 executable (GUI) Intel 80386, for MS Windows"),
    );

    const capaJson = JSON.stringify({
      rules: {
        "create HTTP request": {
          meta: { namespace: "communication/http/client" },
          matches: [capaFeatureMatch("api")],
        },
        "linked against CPP regex library": {
          meta: { namespace: "linking/static/cppregex" },
          matches: [capaFeatureMatch("string")],
        },
      },
    });

    // Return capa's JSON for the capa command; generic output for every other tool.
    vi.mocked(deps.connector.executeShell).mockImplementation(async (cmd: string) =>
      cmd.startsWith("capa") ? ok(capaJson) : ok("output"),
    );

    const result = await handleAnalyzeFile(deps, { file: "test.exe", depth: "standard" });
    const env = parseEnvelope(result);

    expect(env.success).toBe(true);
    const ce = env.data.capability_evidence;
    expect(ce).toBeDefined();
    expect(ce.behavior_capable).toContain("create HTTP request");
    expect(ce.artifact_only).toContain("linked against CPP regex library");
    expect(ce.behavior_capable).not.toContain("linked against CPP regex library");
  });
});

describe("generateNextSteps — no /tmp leak in model-facing step hints", () => {
  it("PCAP steps use the %OUTPUT% sentinel, never /tmp", () => {
    const steps = generateNextSteps("PCAP", "standard", [], [], 0);
    expect(steps.join("\n")).not.toContain("/tmp");
    expect(steps.some((s) => s.includes("%OUTPUT%/http-objects"))).toBe(true);
  });

  it("PCAP steps point beyond tshark to stream/file carving tools", () => {
    // deep tier has no depth-suggestion prefix, so all five PCAP pointers survive the 5-step cap
    const steps = generateNextSteps("PCAP", "deep", [], [], 0).join("\n");
    expect(steps).toContain("tcpflow -r <file> -o %OUTPUT%/tcpflow");
    expect(steps).toContain("tcpxtract -f <file> -o %OUTPUT%/carved");
    expect(steps).toContain("ngrep -I <file>");
    // file-producing carvers must resolve output via the sentinel, never /tmp
    expect(steps).not.toContain("/tmp");
  });

  it("no category leaks a /tmp path in its steps", () => {
    const categories = [
      "PE",
      "PDF",
      "JavaScript",
      "PCAP",
      "Memory",
      "Shellcode",
      "DataWithPEExtension",
    ];
    for (const cat of categories) {
      const steps = generateNextSteps(cat, "deep", [], [], 1);
      expect(steps.join("\n"), `category ${cat}`).not.toContain("/tmp");
    }
  });
});
