import { describe, it, expect, vi } from "vitest";
import { handleCompareFiles } from "../compare-files.js";
import { createMockDeps, ok, parseEnvelope } from "./helpers.js";
import type { HandlerDeps } from "../types.js";

function readpe(funcs: string[]) {
  return JSON.stringify({ "Imported functions": [{ Name: "K.dll", Functions: funcs.map((Name) => ({ Name })) }] });
}
function iSj(names: string[]) {
  return JSON.stringify(names.map((name, i) => ({ name, vaddr: 0x1000 + i * 0x100, vsize: 0x80, perm: "-r-x" })));
}
function capa(caps: string[]) {
  return JSON.stringify({ rules: Object.fromEntries(caps.map((c) => [c, { meta: {} }])) });
}
function diec(compiler: string, packer?: string) {
  const values = [{ name: compiler, type: "Compiler" }];
  if (packer) values.push({ name: packer, type: "Packer" });
  return JSON.stringify({ detects: [{ values }] });
}

/** Route each command to A's or B's data based on which sample path it targets. */
function mockConn(deps: HandlerDeps) {
  const pick = (cmd: string[], a: string, b: string) => (cmd.some((x) => x.includes("a.bin")) ? a : b);
  vi.mocked(deps.connector.execute).mockImplementation(async (cmd) => {
    const c = cmd as string[];
    if (c[0] === "test") return ok("", 0);
    if (c[0] === "file") return ok(pick(c, "/s/a.bin: PE32 executable Intel 80386, for MS Windows", "/s/b.bin: PE32+ executable x86-64, for MS Windows"));
    if (c[0] === "sha256sum") return ok(pick(c, "aaa  /s/a.bin", "bbb  /s/b.bin"));
    if (c[0] === "stat") return ok(pick(c, "1000", "4000"));
    if (c[0] === "python3") return ok(pick(c, "6.0", "7.7"));
    if (c[0] === "diec") return ok(pick(c, diec("MSVC"), diec("MinGW", "UPX")));
    if (c[0] === "readpe") return ok(pick(c, readpe(["InternetOpenW", "RegSetValueExW"]), readpe(["RegSetValueExW", "WriteProcessMemory"])));
    if (c[0] === "r2") return ok(pick(c, iSj([".text", ".rdata"]), iSj([".text", ".reloc"])));
    if (c[0] === "capa") return ok(pick(c, capa(["connect to URL"]), capa(["inject process"])));
    return ok("");
  });
}

describe("compare_files", () => {
  it("produces a structured diff across imports, capabilities, arch, compiler, packer, sections", async () => {
    const deps = createMockDeps({ samplesDir: "/s" });
    mockConn(deps);
    const env = parseEnvelope(await handleCompareFiles(deps, { file_a: "a.bin", file_b: "b.bin" }));

    expect(env.success).toBe(true);
    const d = env.data.diff;
    expect(d.architecture).toEqual({ a: "x86", b: "x64" });
    expect(d.compiler).toEqual({ a: "MSVC", b: "MinGW" });
    expect(d.packer).toEqual({ a: undefined, b: "UPX" });
    expect(d.size_delta).toBe(3000);
    expect(d.entropy_delta).toBeCloseTo(1.7, 3);
    expect(d.imports.added).toContain("WriteProcessMemory");
    expect(d.imports.removed).toContain("InternetOpenW");
    expect(d.capabilities.added).toContain("inject process");
    expect(d.sections.added).toContain(".reloc");
  });

  it("skips the capability diff at depth='quick'", async () => {
    const deps = createMockDeps({ samplesDir: "/s" });
    mockConn(deps);
    const env = parseEnvelope(await handleCompareFiles(deps, { file_a: "a.bin", file_b: "b.bin", depth: "quick" }));
    expect(env.data.diff.capabilities).toBeUndefined();
    // capa must NOT have been invoked in quick mode.
    const calledCapa = vi.mocked(deps.connector.execute).mock.calls.some((c) => (c[0] as string[])[0] === "capa");
    expect(calledCapa).toBe(false);
  });
});
