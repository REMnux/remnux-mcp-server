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
});
