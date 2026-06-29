import { describe, it, expect, vi } from "vitest";
import { handleCheckBehaviorPrerequisites } from "../check-behavior-prerequisites.js";
import { createMockDeps, ok, parseEnvelope } from "./helpers.js";
import type { HandlerDeps } from "../types.js";

const PE = "/samples/x.exe: PE32 executable (GUI) Intel 80386, for MS Windows";

function readpe(libs: Array<{ Name: string; Functions: Array<{ Name: string }> }>) {
  return JSON.stringify({ "Imported functions": libs });
}

function mockConn(
  deps: HandlerDeps,
  opts: { fileType: string; importsJson: string; diecJson: string },
) {
  vi.mocked(deps.connector.execute).mockImplementation(async (cmd) => {
    const c = cmd as string[];
    if (c[0] === "test") return ok("", 0);
    if (c[0] === "file") return ok(opts.fileType);
    if (c[0] === "readpe") return ok(opts.importsJson);
    if (c[0] === "diec") return ok(opts.diecJson);
    return ok("");
  });
}

describe("check_behavior_prerequisites", () => {
  it("capable_statically for http_c2_wininet; possibly_via_dynamic_resolution for clipboard", async () => {
    const deps = createMockDeps();
    mockConn(deps, {
      fileType: PE,
      importsJson: readpe([
        {
          Name: "WININET.dll",
          Functions: [
            { Name: "InternetOpenW" },
            { Name: "InternetOpenUrlW" },
            { Name: "HttpQueryInfoW" },
            { Name: "InternetReadFile" },
          ],
        },
        { Name: "KERNEL32.dll", Functions: [{ Name: "GetProcAddress" }, { Name: "LoadLibraryExW" }] },
      ]),
      diecJson: JSON.stringify({ detects: [{ values: [{ name: "Microsoft Visual C/C++", type: "Compiler" }] }] }),
    });

    const env = parseEnvelope(await handleCheckBehaviorPrerequisites(deps, { file: "x.exe" }));
    expect(env.success).toBe(true);
    expect(env.data.is_pe).toBe(true);
    expect(env.data.packer_detected).toBe(false);
    expect(env.data.dynamic_resolution_present).toBe(true);

    const verdicts = Object.fromEntries(
      env.data.results.map((r: { behavior: string; static_capability: string }) => [r.behavior, r.static_capability]),
    );
    expect(verdicts.http_c2_wininet).toBe("capable_statically");
    expect(verdicts.clipboard_hijacking).toBe("possibly_via_dynamic_resolution");
  });

  it("returns analysis_incomplete on a packed binary instead of a false negative", async () => {
    const deps = createMockDeps();
    mockConn(deps, {
      fileType: PE,
      importsJson: readpe([
        {
          Name: "KERNEL32.dll",
          Functions: [{ Name: "LoadLibraryA" }, { Name: "GetProcAddress" }, { Name: "VirtualProtect" }, { Name: "ExitProcess" }],
        },
      ]),
      diecJson: JSON.stringify({ detects: [{ values: [{ name: "UPX", type: "Packer" }] }] }),
    });

    const env = parseEnvelope(
      await handleCheckBehaviorPrerequisites(deps, { file: "x.exe", behavior: "clipboard_hijacking" }),
    );
    expect(env.data.packer_detected).toBe(true);
    expect(env.data.results[0].static_capability).toBe("analysis_incomplete");
  });

  it("returns analysis_incomplete (managed) for a .NET assembly, not a false negative", async () => {
    const deps = createMockDeps();
    mockConn(deps, {
      fileType: "/samples/x.exe: PE32 executable (GUI) Intel 80386 Mono/.Net assembly, for MS Windows",
      importsJson: readpe([{ Name: "mscoree.dll", Functions: [{ Name: "_CorExeMain" }] }]),
      diecJson: JSON.stringify({ detects: [{ values: [{ name: ".NET", type: "Library" }] }] }),
    });

    const env = parseEnvelope(
      await handleCheckBehaviorPrerequisites(deps, { file: "x.exe", behavior: "clipboard_hijacking" }),
    );
    expect(env.data.is_pe).toBe(true);
    expect(env.data.managed).toBe(true);
    expect(env.data.results[0].static_capability).toBe("analysis_incomplete");
    expect(env.data.results[0].rationale).toMatch(/\.NET|managed/i);
  });

  it("returns not_applicable for a non-PE file", async () => {
    const deps = createMockDeps();
    mockConn(deps, { fileType: "/samples/x.sh: POSIX shell script, ASCII text", importsJson: "", diecJson: "" });

    const env = parseEnvelope(
      await handleCheckBehaviorPrerequisites(deps, { file: "x.sh", behavior: "clipboard_hijacking" }),
    );
    expect(env.data.is_pe).toBe(false);
    expect(env.data.results[0].static_capability).toBe("not_applicable");
  });

  it("treats a PE with an empty import table as obscured (analysis_incomplete)", async () => {
    const deps = createMockDeps();
    mockConn(deps, { fileType: PE, importsJson: readpe([]), diecJson: "" });

    const env = parseEnvelope(
      await handleCheckBehaviorPrerequisites(deps, { file: "x.exe", behavior: "http_c2_wininet" }),
    );
    expect(env.data.packer_detected).toBe(true);
    expect(env.data.results[0].static_capability).toBe("analysis_incomplete");
  });

  it("errors on an unknown behavior and lists the valid ones", async () => {
    const deps = createMockDeps();
    const env = parseEnvelope(
      await handleCheckBehaviorPrerequisites(deps, { file: "x.exe", behavior: "teleportation" }),
    );
    expect(env.success).toBe(false);
    expect(JSON.stringify(env)).toMatch(/clipboard_hijacking/);
  });
});
