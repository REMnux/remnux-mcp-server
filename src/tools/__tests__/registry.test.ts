import { describe, it, expect } from "vitest";
import { toolRegistry } from "../registry.js";

describe("ToolRegistry", () => {
  it("has tools registered", () => {
    expect(toolRegistry.size).toBeGreaterThan(0);
  });

  it("looks up a tool by name", () => {
    const tool = toolRegistry.get("peframe");
    expect(tool).toBeDefined();
    expect(tool!.name).toBe("peframe");
    expect(tool!.description).toBeTruthy();
    expect(tool!.command).toBeTruthy();
  });

  it("returns undefined for unknown tool", () => {
    expect(toolRegistry.get("nonexistent-tool")).toBeUndefined();
  });

  it("has() returns correct results", () => {
    expect(toolRegistry.has("peframe")).toBe(true);
    expect(toolRegistry.has("nonexistent")).toBe(false);
  });

  it("filters by tag", () => {
    const peTools = toolRegistry.byTag("pe");
    expect(peTools.length).toBeGreaterThan(0);
    for (const t of peTools) {
      expect(t.tags).toContain("pe");
    }
  });

  it("filters by tier (quick includes only quick tools)", () => {
    const quickTools = toolRegistry.byTier("quick");
    for (const t of quickTools) {
      expect(t.tier).toBe("quick");
    }
  });

  it("filters by tier (deep includes all tiers)", () => {
    const deepTools = toolRegistry.byTier("deep");
    const allTools = toolRegistry.all();
    expect(deepTools.length).toBe(allTools.length);
  });

  it("filters by tag and tier", () => {
    const tools = toolRegistry.byTagAndTier("pe", "standard");
    for (const t of tools) {
      expect(t.tags).toContain("pe");
      expect(["quick", "standard"]).toContain(t.tier);
    }
  });

  it("runs webcrack in the JavaScript standard chain before box-js", () => {
    const names = toolRegistry.byTagAndTier("javascript", "standard").map((t) => t.name);
    expect(names).toContain("webcrack");
    expect(names).toContain("box-js");
    // webcrack (primary, static) must run before box-js (secondary, dynamic)
    expect(names.indexOf("webcrack")).toBeLessThan(names.indexOf("box-js"));
  });

  it("webcrack auto-run uses stdout mode (no -o / %OUTPUT% args)", () => {
    const webcrack = toolRegistry
      .byTagAndTier("javascript", "standard")
      .find((t) => t.name === "webcrack");
    expect(webcrack).toBeDefined();
    // webcrack refuses a pre-existing -o dir, and analyze_file pre-creates
    // %OUTPUT% dirs — so the auto-run must stay sentinel-free.
    const args = [...(webcrack?.fixedArgs ?? []), ...(webcrack?.suffixArgs ?? [])];
    expect(args.join(" ")).not.toContain("-o");
    expect(args.join(" ")).not.toContain("%OUTPUT%");
  });

  it("raises box-js above its 10-second default timeout via fixedArgs", () => {
    const boxjs = toolRegistry
      .byTagAndTier("javascript", "standard")
      .find((t) => t.name === "box-js");
    expect(boxjs?.fixedArgs).toEqual(expect.arrayContaining(["--timeout", "60"]));
  });

  it("all tools have required fields", () => {
    for (const tool of toolRegistry.all()) {
      expect(tool.name).toBeTruthy();
      expect(tool.description).toBeTruthy();
      expect(tool.command).toBeTruthy();
      expect(["positional", "flag", "stdin"]).toContain(tool.inputStyle);
      expect(["text", "json"]).toContain(tool.outputFormat);
      expect(tool.timeout).toBeGreaterThan(0);
      expect(["quick", "standard", "deep"]).toContain(tool.tier);
    }
  });

  it("has memory forensics tools tagged with 'memory'", () => {
    const memTools = toolRegistry.byTag("memory");
    expect(memTools.length).toBeGreaterThanOrEqual(6);
    const names = memTools.map((t) => t.name);
    expect(names).toContain("vol3-info");
    expect(names).toContain("vol3-pslist");
    expect(names).toContain("vol3-pstree");
    expect(names).toContain("vol3-netscan");
    expect(names).toContain("vol3-cmdline");
    expect(names).toContain("vol3-malfind");
  });

  it("vol3 tools use flag inputStyle with -f flag and suffixArgs", () => {
    const vol3info = toolRegistry.get("vol3-info");
    expect(vol3info).toBeDefined();
    expect(vol3info!.inputStyle).toBe("flag");
    expect(vol3info!.inputFlag).toBe("-f");
    expect(vol3info!.suffixArgs).toEqual(["windows.info"]);
  });

  it("registers r2ghidra for native PE/ELF decompilation at deep tier only", () => {
    const r2g = toolRegistry.get("r2ghidra");
    expect(r2g).toBeDefined();
    expect(r2g!.command).toBe("r2");
    expect(r2g!.tier).toBe("deep");
    expect(r2g!.requiresUserArgs).toBe(true);
    expect(r2g!.tags).toEqual(expect.arrayContaining(["pe", "elf", "decompilation"]));

    expect(toolRegistry.byTagAndTier("pe", "deep").map((t) => t.name)).toContain("r2ghidra");
    expect(toolRegistry.byTagAndTier("elf", "deep").map((t) => t.name)).toContain("r2ghidra");
    // deep-tier tool: not surfaced during quick/standard analysis
    expect(toolRegistry.byTagAndTier("pe", "standard").map((t) => t.name)).not.toContain("r2ghidra");
  });

  it("marks cfr and jadx with the cross-cutting 'decompilation' tag", () => {
    expect(toolRegistry.get("cfr")!.tags).toContain("decompilation");
    expect(toolRegistry.get("jadx")!.tags).toContain("decompilation");
  });

  it("registers PCAP triage presets (capinfos at quick, tshark-tls at standard)", () => {
    const names = toolRegistry.byTag("pcap").map((t) => t.name);
    expect(names).toContain("capinfos");
    expect(names).toContain("tshark-tls");

    const capinfos = toolRegistry.get("capinfos")!;
    expect(capinfos.command).toBe("capinfos");
    expect(capinfos.inputStyle).toBe("positional");
    expect(capinfos.tier).toBe("quick");
    expect(capinfos.tags).toEqual(expect.arrayContaining(["pcap", "triage"]));

    const tls = toolRegistry.get("tshark-tls")!;
    expect(tls.command).toBe("tshark");
    expect(tls.tier).toBe("standard");

    const fp = toolRegistry.get("tshark-fingerprint")!;
    expect(fp.command).toBe("tshark");
    expect(fp.tier).toBe("standard");
    expect(fp.tags).toContain("pcap");

    // capinfos orients the quick triage; the TLS presets only surface from standard up
    expect(toolRegistry.byTagAndTier("pcap", "quick").map((t) => t.name)).toContain("capinfos");
    expect(toolRegistry.byTagAndTier("pcap", "quick").map((t) => t.name)).not.toContain("tshark-tls");
    expect(toolRegistry.byTagAndTier("pcap", "quick").map((t) => t.name)).not.toContain("tshark-fingerprint");
    expect(toolRegistry.byTagAndTier("pcap", "standard").map((t) => t.name)).toContain("tshark-tls");
    expect(toolRegistry.byTagAndTier("pcap", "standard").map((t) => t.name)).toContain("tshark-fingerprint");
  });
});
