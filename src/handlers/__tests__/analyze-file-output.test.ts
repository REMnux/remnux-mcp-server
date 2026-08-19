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

describe("analyze_file — truncation hints are runnable", () => {
  it("every PARSING_HINT references %OUTPUT%/<file>, never a bare output/<file>", async () => {
    const mod = await import("../analyze-file.js");
    const hints = (mod as unknown as { PARSING_HINTS: Record<string, string[]> }).PARSING_HINTS;
    expect(hints).toBeDefined();
    expect(Object.keys(hints)).toContain("pestr");
    for (const [tool, list] of Object.entries(hints)) {
      expect(list.length, tool).toBeGreaterThan(0);
      for (const h of list) {
        expect(h, `${tool}: ${h}`).toContain("%OUTPUT%/<file>");
        expect(h, `${tool}: ${h}`).not.toMatch(/(^|[^%])output\/<file>/);
      }
    }
  });

  it("oversized strings output carries a %OUTPUT% saved-file marker and query hint (full mode)", async () => {
    const deps = createMockDeps({ outputDir: "/output" });
    // strings runs in the quick tier for JavaScript (not PE, where pestr replaces it)
    vi.mocked(deps.connector.execute).mockResolvedValue(
      ok("/samples/a.js: JavaScript source, ASCII text"),
    );
    // strings has a 15KB display budget; 20KB keeps the whole response under the summary threshold
    const big = "str\n".repeat(5000);
    vi.mocked(deps.connector.executeShell).mockImplementation(async (cmd: string) =>
      cmd.startsWith("strings") ? ok(big) : ok("output"),
    );

    const result = await handleAnalyzeFile(deps, { file: "a.js", depth: "quick" });
    const env = parseEnvelope(result);
    expect(env.data.mode).toBeUndefined();
    const strings = env.data.tools_run.find((t: { name: string }) => t.name === "strings");
    expect(strings).toBeDefined();
    expect(strings.truncated).toBe(true);
    expect(strings.output).toContain("%OUTPUT%/strings-a.js.txt");
    expect(strings.output).toContain("[Query with:");
    expect(strings.output).not.toMatch(/[^%]output\/strings-a\.js\.txt/);
    expect(deps.connector.writeFile).toHaveBeenCalledWith("/output/strings-a.js.txt", expect.anything());
  });

  it("oversized pestr output in summary mode still reports saved_to from the new marker", async () => {
    const deps = createMockDeps({ outputDir: "/output" });
    vi.mocked(deps.connector.execute).mockResolvedValue(
      ok("/samples/test.exe: PE32 executable (GUI) Intel 80386, for MS Windows"),
    );
    const big = Array.from({ length: 6000 }, (_, i) => `0x${i.toString(16)} .rdata str${i}`).join("\n");
    vi.mocked(deps.connector.executeShell).mockImplementation(async (cmd: string) =>
      cmd.startsWith("pestr") ? ok(big) : ok("output"),
    );

    const result = await handleAnalyzeFile(deps, { file: "test.exe", depth: "quick" });
    const env = parseEnvelope(result);
    expect(env.data.mode).toBe("summary");
    const pestr = env.data.tools.find((t: { name: string }) => t.name === "pestr");
    expect(pestr).toBeDefined();
    expect(pestr.saved_to).toBe("pestr-test.exe.txt");
    expect(env.data.full_output_hint).toContain("pestr-test.exe.txt");
    expect(deps.connector.writeFile).toHaveBeenCalledWith("/output/pestr-test.exe.txt", expect.anything());
  });
});

describe("analyze_file — spill failure degrades to a fileless marker", () => {
  it("keeps the truncation marker without a saved-file reference when the write fails", async () => {
    const deps = createMockDeps({ outputDir: "/output" });
    vi.mocked(deps.connector.execute).mockResolvedValue(ok("/samples/a.js: JavaScript source, ASCII text"));
    vi.mocked(deps.connector.executeShell).mockImplementation(async (cmd: string) =>
      cmd.startsWith("strings") ? ok("str\n".repeat(5000)) : ok("output"),
    );
    vi.mocked(deps.connector.writeFile).mockRejectedValue(new Error("EACCES"));
    const env = parseEnvelope(await handleAnalyzeFile(deps, { file: "a.js", depth: "quick" }));
    const strings = env.data.tools_run.find((t: { name: string }) => t.name === "strings");
    expect(strings.truncated).toBe(true);
    expect(strings.output).toContain("[Truncated at");
    expect(strings.output).not.toContain("Saved in full");
  });
});
