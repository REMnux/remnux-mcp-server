/**
 * analyze_file's handling of yara-forge in summary mode.
 *
 * An unmatched scan writes nothing, and the server's "(no output)" placeholder used
 * to be read as a match, so every PE was reported as matching a family signature.
 * A matched scan had no parser, so its rule names reached the summary nowhere.
 * Rule names below are synthetic.
 */

import { describe, it, expect, vi } from "vitest";
import { handleAnalyzeFile, spillFilename } from "../analyze-file.js";
import { createMockDeps, ok, fail, parseEnvelope } from "./helpers.js";

const RULES = ["VENDORA_Win_Family", "VENDORA_Win_FamilyStrings", "VENDORB_Win_Family_Auto"];
const TOKEN = "YARA family signature matched";
/** Pushes the run past the 32 KB summary threshold. */
const BULK = "section .text loaded at 0x401000\n".repeat(1100);

type Result = { stdout: string; stderr: string; exitCode: number };

/** The path the handler passed to yara-forge. yara prints it back on every match line. */
const targetOf = (cmd: string) => cmd.match(/'([^']+)'/)?.[1] ?? "";

async function run(yara: (target: string) => Result) {
  const deps = createMockDeps();
  vi.mocked(deps.connector.execute).mockResolvedValue(
    ok("/samples/sample.exe: PE32 executable (GUI) Intel 80386, for MS Windows"),
  );
  vi.mocked(deps.connector.executeShell).mockImplementation(async (cmd: string) => {
    if (cmd.startsWith("yara-forge")) return yara(targetOf(cmd));
    if (cmd.startsWith("pestr")) return ok(BULK);
    return ok("clean");
  });
  const env = parseEnvelope(await handleAnalyzeFile(deps, { file: "sample.exe", depth: "standard" }));
  expect(env.data.mode).toBe("summary");
  const tool = env.data.tools.find((t: { name: string }) => t.name === "yara-forge");
  expect(tool, "yara-forge must be in the standard PE chain").toBeDefined();
  return { data: env.data, tool, deps };
}

const advisoryIssues = (data: { action_required?: Array<{ issue: string }> }) =>
  (data.action_required ?? []).map((a) => a.issue).join("\n");

describe("analyze_file: yara-forge in summary mode", () => {
  it("reports an unmatched scan as clean, with no family token or advisory", async () => {
    const { data, tool } = await run(() => ok(""));
    expect(tool.status).toBe("clean");
    expect(data.triage_summary).not.toContain(TOKEN);
    expect(advisoryIssues(data)).not.toContain("YARA family signatures matched");
  });

  it("reports every matched rule by name, with the token, the advisory and a saved match list", async () => {
    const { data, tool, deps } = await run((target) => ok(RULES.map((r) => `${r} ${target}`).join("\n")));
    expect(tool.status).toBe("findings");
    for (const rule of RULES) expect(tool.key_lines).toContain(`YARA family signature: ${rule}`);
    expect(data.triage_summary).toContain(TOKEN);
    expect(advisoryIssues(data)).toContain("YARA family signatures matched");

    const file = spillFilename("yara-forge", "sample.exe");
    expect(tool.saved_to).toBe(file);
    expect(data.full_output_hint).toContain(file);
    const written = vi.mocked(deps.connector.writeFile).mock.calls.find(([path]) => path === `/output/${file}`);
    for (const rule of RULES) expect(String(written?.[1])).toContain(rule);
  });

  it("does not read a scan error as a match", async () => {
    const { data, tool } = await run((target) => fail(`error scanning ${target}: could not open file`));
    expect(tool.status).toBe("error");
    expect(data.triage_summary).not.toContain(TOKEN);
  });
});

describe("spillFilename", () => {
  it("keeps samples whose names sanitize identically apart", () => {
    // Every non-Latin letter sanitizes to "_", so both would otherwise be "____.exe".
    expect(spillFilename("yara-forge", "счет.exe")).not.toBe(spillFilename("yara-forge", "план.exe"));
  });

  it("stays within one 255-byte path component", () => {
    expect(spillFilename("yara-forge", "a".repeat(400)).length).toBeLessThanOrEqual(255);
  });
});
