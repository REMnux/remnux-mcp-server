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

    await handleAnalyzeFile(deps, { file: "a.js", depth: "standard" });

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

    const result = await handleAnalyzeFile(deps, { file: "a.js", depth: "standard" });
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

describe("generateNextSteps — no /tmp leak in model-facing step hints", () => {
  it("PCAP steps use the %OUTPUT% sentinel, never /tmp", () => {
    const steps = generateNextSteps("PCAP", "standard", [], [], 0);
    expect(steps.join("\n")).not.toContain("/tmp");
    expect(steps.some((s) => s.includes("%OUTPUT%/http-objects"))).toBe(true);
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
