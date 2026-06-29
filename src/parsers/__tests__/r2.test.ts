import { describe, it, expect } from "vitest";
import {
  parseR2Strings,
  parseR2Sections,
  parseR2Functions,
  parseR2Xrefs,
  parseR2Version,
  splitMarkedR2Output,
  R2_MARKERS,
} from "../r2.js";

describe("parseR2Strings (izj/izzj)", () => {
  it("extracts value, vaddr, section", () => {
    const json = JSON.stringify([
      { vaddr: 0x402048, section: ".rodata", type: "ascii", string: "hello" },
      { vaddr: 0x402020, section: ".rodata", string: "world" },
    ]);
    const out = parseR2Strings(json);
    expect(out).toHaveLength(2);
    expect(out[0]).toEqual({ value: "hello", vaddr: 0x402048, section: ".rodata" });
    expect(out[1].section).toBe(".rodata");
  });

  it("is fail-soft on malformed entries and invalid JSON", () => {
    expect(parseR2Strings("not json")).toEqual([]);
    expect(parseR2Strings(JSON.stringify([null, 5, { vaddr: 1 }, { string: "x" }]))).toEqual([]);
  });
});

describe("parseR2Sections (iSj)", () => {
  it("computes vaddrEnd and the exec flag from perm", () => {
    const json = JSON.stringify([
      { name: ".text", vaddr: 0x1000, vsize: 0x200, perm: "-r-x" },
      { name: ".rdata", vaddr: 0x2000, vsize: 0x100, perm: "-r--" },
    ]);
    const out = parseR2Sections(json);
    expect(out[0]).toEqual({ name: ".text", vaddr: 0x1000, vaddrEnd: 0x1200, exec: true });
    expect(out[1].exec).toBe(false);
  });
});

describe("parseR2Functions (aflj)", () => {
  it("reads the function address from `addr` or `offset`", () => {
    expect(parseR2Functions(JSON.stringify([{ addr: 0x1136, name: "main", size: 10 }]))[0].addr).toBe(0x1136);
    expect(parseR2Functions(JSON.stringify([{ offset: 0x1200, name: "f", size: 5 }]))[0].addr).toBe(0x1200);
  });
});

describe("parseR2Xrefs (axtj)", () => {
  it("extracts from/type/fcn/opcode (the real radare2 6.1.6 shape)", () => {
    const json = JSON.stringify([
      {
        from: 4198718,
        type: "STRN",
        perm: "r--",
        opcode: "lea rax, str.hello",
        fcn_addr: 4198710,
        fcn_name: "main",
      },
    ]);
    const out = parseR2Xrefs(json);
    expect(out).toHaveLength(1);
    expect(out[0]).toMatchObject({ from: 4198718, type: "STRN", fcnAddr: 4198710, fcnName: "main", opcode: "lea rax, str.hello" });
  });

  it("returns [] for an empty array and skips entries without `from`", () => {
    expect(parseR2Xrefs("[]")).toEqual([]);
    expect(parseR2Xrefs(JSON.stringify([{ type: "DATA" }]))).toEqual([]);
  });
});

describe("parseR2Version", () => {
  it("extracts the version token", () => {
    expect(parseR2Version("radare2 6.1.6 +1 abi:107 @ linux-x86_64")).toBe("6.1.6");
    expect(parseR2Version("garbage")).toBeUndefined();
  });
});

describe("splitMarkedR2Output", () => {
  it("splits version / sections / functions / per-vaddr xrefs on the markers", () => {
    const stdout = [
      "radare2 6.1.6 +1 abi:107 @ linux-x86_64",
      R2_MARKERS.sections,
      '[{"name":".text","vaddr":4096,"vsize":512,"perm":"-r-x"}]',
      R2_MARKERS.functions,
      '[{"addr":4150,"name":"main","size":10}]',
      `${R2_MARKERS.xref} 0x402048`,
      '[{"from":4198718,"type":"STRN","fcn_name":"main"}]',
      `${R2_MARKERS.xref} 0x402020`,
      "[]",
    ].join("\n");
    const s = splitMarkedR2Output(stdout);
    expect(s.version).toBe("6.1.6");
    expect(s.truncated).toBe(false);
    expect(parseR2Sections(s.sectionsJson)).toHaveLength(1);
    expect(parseR2Functions(s.functionsJson)[0].name).toBe("main");
    expect(parseR2Xrefs(s.xrefsByVaddr.get("0x402048")!)).toHaveLength(1);
    expect(s.xrefsByVaddr.get("0x402020")).toBe("[]");
  });

  it("flags connector truncation", () => {
    const s = splitMarkedR2Output("some output\n[OUTPUT TRUNCATED - exceeded 10MB limit]");
    expect(s.truncated).toBe(true);
  });
});
