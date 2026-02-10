import { describe, it, expect } from "vitest";
import { toolCatalog } from "../index.js";

describe("ToolCatalog", () => {
  it("loads the tools index", () => {
    expect(toolCatalog.size).toBeGreaterThan(100);
  });

  it("has version and updated fields", () => {
    expect(toolCatalog.version).toBe("1.0.0");
    expect(toolCatalog.updated).toMatch(/^\d{4}-\d{2}-\d{2}$/);
  });

  it("returns all tools", () => {
    const all = toolCatalog.all();
    expect(all.length).toBe(toolCatalog.size);
    expect(all[0]).toHaveProperty("command");
    expect(all[0]).toHaveProperty("name");
    expect(all[0]).toHaveProperty("category");
    expect(all[0]).toHaveProperty("description");
  });

  it("lists categories", () => {
    const cats = toolCatalog.categories();
    expect(cats.length).toBeGreaterThan(10);
    expect(cats).toContain("Examine Static Properties: PE Files");
    expect(cats).toContain("Analyze Documents: PDF");
  });

  it("filters by salt-states category", () => {
    const peTools = toolCatalog.forSaltCategory("Examine Static Properties: PE Files");
    expect(peTools.length).toBeGreaterThan(0);
    for (const t of peTools) {
      expect(t.category).toBe("Examine Static Properties: PE Files");
    }
  });

  it("filters by MCP category", () => {
    const peTools = toolCatalog.forMcpCategory("PE");
    expect(peTools.length).toBeGreaterThan(0);
    // PE maps to multiple salt-states categories
    const cats = new Set(peTools.map((t) => t.category));
    expect(cats.size).toBeGreaterThanOrEqual(1);
  });

  it("returns empty array for unknown MCP category", () => {
    expect(toolCatalog.forMcpCategory("NONEXISTENT")).toEqual([]);
  });

  it("returns empty array for unknown salt-states category", () => {
    expect(toolCatalog.forSaltCategory("Fake Category")).toEqual([]);
  });

  // ── New category mappings (Python, Go→ELF, Android→APK) ──────────────

  it("maps 'Statically Analyze Code: Python' to MCP Python category", () => {
    const pythonTools = toolCatalog.forMcpCategory("Python");
    const saltCats = new Set(pythonTools.map((t) => t.category));
    expect(saltCats).toContain("Statically Analyze Code: Python");
  });

  it("maps Go salt-states category to ELF when tools exist", () => {
    // "Examine Static Properties: Go" is mapped to ELF in SALT_TO_MCP_CATEGORY.
    // Once update-docs.py syncs redress into tools-index.json, Go tools will
    // appear in forMcpCategory("ELF"). For now verify ELF includes its base categories.
    const elfTools = toolCatalog.forMcpCategory("ELF");
    expect(elfTools.length).toBeGreaterThan(0);
    const saltCats = new Set(elfTools.map((t) => t.category));
    expect(saltCats).toContain("Examine Static Properties: ELF Files");
  });

  it("maps 'Statically Analyze Code: Android' to MCP APK category", () => {
    const apkTools = toolCatalog.forMcpCategory("APK");
    const saltCats = new Set(apkTools.map((t) => t.category));
    expect(saltCats).toContain("Statically Analyze Code: Android");
  });
});
