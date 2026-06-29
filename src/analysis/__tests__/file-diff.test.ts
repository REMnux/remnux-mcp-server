import { describe, it, expect } from "vitest";
import { diffFileMeta, type FileMeta } from "../file-diff.js";

function meta(over: Partial<FileMeta> = {}): FileMeta {
  return {
    file: "a.bin",
    file_type: "PE32 executable",
    sha256: "aaa",
    size_bytes: 1000,
    arch: "x86",
    entropy: 6.0,
    compiler: "MSVC",
    packer: undefined,
    imports: ["InternetOpenW", "RegSetValueExW"],
    import_count: 2,
    capabilities: ["connect to URL"],
    capa_run: true,
    sections: [".text", ".rdata"],
    ...over,
  };
}

describe("diffFileMeta", () => {
  it("diffs imports, capabilities, and sections (added/removed/common)", () => {
    const a = meta();
    const b = meta({
      imports: ["RegSetValueExW", "WriteProcessMemory"],
      capabilities: ["connect to URL", "inject process"],
      sections: [".text", ".reloc"],
    });
    const d = diffFileMeta(a, b);
    expect(d.imports.added).toEqual(["WriteProcessMemory"]);
    expect(d.imports.removed).toEqual(["InternetOpenW"]);
    expect(d.imports.common_count).toBe(1);
    expect(d.capabilities?.added).toEqual(["inject process"]);
    expect(d.sections.added).toEqual([".reloc"]);
    expect(d.sections.removed).toEqual([".rdata"]);
  });

  it("reports architecture / compiler / packer / size / entropy changes", () => {
    const d = diffFileMeta(meta(), meta({ arch: "x64", compiler: "MinGW", packer: "UPX", size_bytes: 2500, entropy: 7.7 }));
    expect(d.architecture).toEqual({ a: "x86", b: "x64" });
    expect(d.compiler).toEqual({ a: "MSVC", b: "MinGW" });
    expect(d.packer).toEqual({ a: undefined, b: "UPX" });
    expect(d.size_delta).toBe(1500);
    expect(d.entropy_delta).toBe(1.7);
    expect(d.notes.join(" ")).toMatch(/toolchain|architecture/i);
  });

  it("omits the capability diff (with a note) unless capa ran on BOTH files", () => {
    const d = diffFileMeta(meta(), meta({ capa_run: false, capabilities: [] }));
    expect(d.capabilities).toBeUndefined();
    expect(d.notes.join(" ")).toMatch(/capa.*depth='standard'/i);
  });

  it("does not flag unchanged fields", () => {
    const d = diffFileMeta(meta(), meta());
    expect(d.architecture).toBeUndefined();
    expect(d.compiler).toBeUndefined();
    expect(d.imports.added).toEqual([]);
    expect(d.imports.removed).toEqual([]);
  });

  it("caps very large added/removed lists", () => {
    const big = Array.from({ length: 150 }, (_, i) => `f${i}`);
    const d = diffFileMeta(meta({ imports: [] }), meta({ imports: big, capa_run: false }));
    expect(d.imports.added).toHaveLength(101); // 100 + overflow marker
    expect(d.imports.added[100]).toMatch(/and 50 more/);
  });
});
