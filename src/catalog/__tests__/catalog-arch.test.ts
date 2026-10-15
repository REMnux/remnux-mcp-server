import { describe, it, expect } from "vitest";
import { toolCatalog, ToolCatalog } from "../index.js";

describe("toolCatalog architecture data", () => {
  it("reads architectures and arch_notes from the bundled index", () => {
    const tracesc = toolCatalog.all().find((t) => t.command === "runsc");
    expect(tracesc?.architectures).toEqual(["amd64"]);
    expect(tracesc?.arch_notes?.arm64).toBeTruthy();
  });

  it("traces an executable to its catalog entry (tracesc -> runsc)", () => {
    expect(toolCatalog.isArchLimited("tracesc")).toBe(true);
    expect(toolCatalog.isArchLimited("runsc")).toBe(true);
    expect(toolCatalog.isArchLimited("capa")).toBe(false);
    expect(toolCatalog.isArchLimited("no-such-tool")).toBe(false);
  });

  it("reports a tool stock arm64 REMnux omits, with the index's alternative", () => {
    expect(toolCatalog.archStatus("tracesc", "arm64")).toEqual({
      included: false,
      note: "Use speakeasy or qiling instead.",
    });
    expect(toolCatalog.absenceNote("tracesc", "arm64")).toBe(
      "Not included in stock arm64 REMnux (installed on amd64 only). Use speakeasy or qiling instead.",
    );
    expect(toolCatalog.limitationNote("tracesc", "arm64")).toBeUndefined();
  });

  it("reports a tool present with reduced function as a limitation, not an absence", () => {
    expect(toolCatalog.archStatus("peepdf", "arm64")).toEqual({
      included: true,
      note: "JavaScript emulation is unavailable.",
    });
    expect(toolCatalog.limitationNote("peepdf", "arm64")).toBe(
      "On arm64 REMnux: JavaScript emulation is unavailable.",
    );
    expect(toolCatalog.absenceNote("peepdf", "arm64")).toBeUndefined();
  });

  it("says nothing on amd64, on an unknown or null architecture, or about an unlimited tool", () => {
    expect(toolCatalog.archStatus("tracesc", "amd64")).toBeUndefined();
    expect(toolCatalog.archStatus("tracesc", "riscv64")).toBeUndefined();
    expect(toolCatalog.archStatus("tracesc", null)).toBeUndefined();
    expect(toolCatalog.archStatus("capa", "arm64")).toBeUndefined();
    expect(toolCatalog.archNote("tracesc", null)).toBeUndefined();
  });

  it("knows every amd64-only executable named in the server's own hints and features", () => {
    for (const exe of ["tracesc", "js_unshroud", "thug", "rar", "trid", "scdbg", "wine"]) {
      expect(toolCatalog.absenceNote(exe, "arm64"), exe).toMatch(/^Not included in stock arm64 REMnux/);
      expect(toolCatalog.absenceNote(exe, "amd64"), exe).toBeUndefined();
    }
  });

  it("treats an older index without architecture fields as the same on every architecture", () => {
    const old = new ToolCatalog({
      version: "1.0.0",
      updated: "2026-01-01",
      tools: [{ command: "runsc", name: "runsc", category: "x", description: "d", website: "https://example.com" }],
    });
    expect(old.isArchLimited("tracesc")).toBe(false);
    expect(old.archStatus("runsc", "arm64")).toBeUndefined();
    expect(old.absenceNote("tracesc", "arm64")).toBeUndefined();
  });
});
