import { describe, it, expect, vi } from "vitest";
import { handleSuggestTools } from "../suggest-tools.js";
import { toolCatalog } from "../../catalog/index.js";
import { toolRegistry } from "../../tools/registry.js";
import { createMockDeps, ok, parseEnvelope } from "./helpers.js";

describe("handleSuggestTools", () => {
  it("returns recommended tools for a PE file", async () => {
    const deps = createMockDeps();
    vi.mocked(deps.connector.execute).mockResolvedValue(
      ok("/samples/test.exe: PE32 executable (GUI) Intel 80386")
    );

    const result = await handleSuggestTools(deps, { file: "test.exe" });
    const env = parseEnvelope(result);
    expect(env.success).toBe(true);
    expect(env.data.matched_category).toBe("PE");
    expect(env.data.recommended_tools.length).toBeGreaterThan(0);
    expect(env.data.analysis_hints).toBeTruthy();
  });

  it("returns recommended tools for a PDF file", async () => {
    const deps = createMockDeps();
    vi.mocked(deps.connector.execute).mockResolvedValue(
      ok("/samples/doc.pdf: PDF document, version 1.4")
    );

    const result = await handleSuggestTools(deps, { file: "doc.pdf" });
    const env = parseEnvelope(result);
    expect(env.data.matched_category).toBe("PDF");
    expect(env.data.recommended_tools.length).toBeGreaterThan(0);
  });

  it("respects depth parameter", async () => {
    const deps = createMockDeps();
    vi.mocked(deps.connector.execute).mockResolvedValue(
      ok("/samples/test.exe: PE32 executable")
    );

    const quick = await handleSuggestTools(deps, { file: "test.exe", depth: "quick" });
    const deep = await handleSuggestTools(deps, { file: "test.exe", depth: "deep" });
    const qEnv = parseEnvelope(quick);
    const dEnv = parseEnvelope(deep);
    expect(dEnv.data.recommended_tools.length).toBeGreaterThanOrEqual(
      qEnv.data.recommended_tools.length
    );
  });

  it("returns error when file command fails", async () => {
    const deps = createMockDeps();
    vi.mocked(deps.connector.execute).mockRejectedValue(new Error("No such file"));

    const result = await handleSuggestTools(deps, { file: "missing.exe" });
    const env = parseEnvelope(result);
    expect(env.success).toBe(false);
  });

  it("returns error for empty file output", async () => {
    const deps = createMockDeps();
    vi.mocked(deps.connector.execute).mockResolvedValue(ok(""));

    const result = await handleSuggestTools(deps, { file: "empty" });
    const env = parseEnvelope(result);
    expect(env.success).toBe(false);
  });

  it("rejects path traversal when sandbox enabled", async () => {
    const deps = createMockDeps();
    const result = await handleSuggestTools(deps, { file: "../etc/passwd" });
    const env = parseEnvelope(result);
    expect(env.success).toBe(false);
  });

  it("includes additional_tools from catalog for PE files", async () => {
    const deps = createMockDeps();
    vi.mocked(deps.connector.execute).mockResolvedValue(
      ok("/samples/test.exe: PE32 executable (GUI) Intel 80386")
    );

    // Catalog should have PE tools beyond the registry
    const catalogPeTools = toolCatalog.forMcpCategory("PE");
    expect(catalogPeTools.length).toBeGreaterThan(0);

    const result = await handleSuggestTools(deps, { file: "test.exe" });
    const env = parseEnvelope(result);
    expect(env.success).toBe(true);
    // additional_tools should be present (catalog has tools beyond registry)
    expect(env.data.additional_tools).toBeDefined();
    expect(Array.isArray(env.data.additional_tools)).toBe(true);
    {
      // Each entry is a discovery pointer (name + description + website), NOT a
      // runnable command — the misleading `command` slug must be gone.
      for (const tool of env.data.additional_tools) {
        expect(tool).toHaveProperty("name");
        expect(tool).toHaveProperty("description");
        expect(tool).toHaveProperty("website");
        expect(tool).not.toHaveProperty("command");
      }
    }
  });

  it("deduplicates .py-suffixed tools between registry and catalog", async () => {
    const deps = createMockDeps();
    vi.mocked(deps.connector.execute).mockResolvedValue(
      ok("/samples/test.exe: PE32 executable (GUI) Intel 80386")
    );

    const result = await handleSuggestTools(deps, { file: "test.exe" });
    const env = parseEnvelope(result);
    expect(env.success).toBe(true);

    // Build registry command set the same way the handler does
    const normalize = (c: string) => c.replace(/\.py$/, '');
    const registryCommands = new Set(
      toolRegistry.byTagAndTier("pe", "standard").map((t) => normalize(t.command))
    );
    // additional_tools no longer surface `command`; map the surfaced display
    // name back to its catalog command to assert the dedup invariant.
    const nameToCommand = new Map(toolCatalog.all().map((c) => [c.name, c.command] as [string, string]));
    const additionalCommands = (env.data.additional_tools ?? [])
      .map((t: { name: string }) => nameToCommand.get(t.name))
      .filter((c: string | undefined): c is string => typeof c === "string");

    // No normalized overlap between registry commands and additional_tools
    for (const cmd of additionalCommands) {
      expect(registryCommands.has(normalize(cmd))).toBe(false);
    }
  });

  it("excludes catalog entries aliased to registry tools", async () => {
    const deps = createMockDeps();
    // additional_tools surface the display `name`, not the catalog `command`
    // slug — map slug → name so the exclusion assertions stay meaningful.
    const commandToName = new Map(toolCatalog.all().map((c) => [c.command, c.name] as [string, string]));
    const surfaces = (
      env: { data?: { additional_tools?: Array<{ name: string }> } },
      slug: string,
    ): boolean => {
      const name = commandToName.get(slug);
      const names = new Set((env.data?.additional_tools ?? []).map((t) => t.name));
      return name !== undefined && names.has(name);
    };

    // PE — readpe-formerly-pev excluded (aliased to pescan/pestr)
    vi.mocked(deps.connector.execute).mockResolvedValue(
      ok("/samples/test.exe: PE32 executable (GUI) Intel 80386")
    );
    const peEnv = parseEnvelope(await handleSuggestTools(deps, { file: "test.exe" }));
    expect(toolCatalog.forMcpCategory("PE").map((t) => t.command)).toContain("readpe-formerly-pev");
    expect(surfaces(peEnv, "readpe-formerly-pev")).toBe(false);

    // PDF — origamindee, pdftk-java excluded at standard depth
    vi.mocked(deps.connector.execute).mockResolvedValue(
      ok("/samples/doc.pdf: PDF document, version 1.4")
    );
    const pdfEnv = parseEnvelope(await handleSuggestTools(deps, { file: "doc.pdf" }));
    const pdfCatalog = toolCatalog.forMcpCategory("PDF").map((t) => t.command);
    expect(pdfCatalog).toContain("origamindee");
    expect(pdfCatalog).toContain("pdftk-java");
    expect(surfaces(pdfEnv, "origamindee")).toBe(false);
    expect(surfaces(pdfEnv, "pdftk-java")).toBe(false);
    // peepdf-3 still appears at standard depth (peepdf is deep-tier only)
    expect(surfaces(pdfEnv, "peepdf-3")).toBe(true);

    // At deep depth, peepdf enters the registry so the peepdf-3 alias is hidden
    const pdfDeepEnv = parseEnvelope(await handleSuggestTools(deps, { file: "doc.pdf", depth: "deep" }));
    expect(surfaces(pdfDeepEnv, "peepdf-3")).toBe(false);

    // OLE2 — oletools, xlmmacrodeobfuscator excluded
    vi.mocked(deps.connector.execute).mockResolvedValue(
      ok("/samples/doc.doc: Composite Document File V2 Document")
    );
    const oleEnv = parseEnvelope(await handleSuggestTools(deps, { file: "doc.doc" }));
    const oleCatalog = toolCatalog.forMcpCategory("OLE2").map((t) => t.command);
    expect(oleCatalog).toContain("oletools");
    expect(oleCatalog).toContain("xlmmacrodeobfuscator");
    expect(surfaces(oleEnv, "oletools")).toBe(false);
    expect(surfaces(oleEnv, "xlmmacrodeobfuscator")).toBe(false);

    // Python — decompyle, pyinstaller-extractor excluded (aliased)
    vi.mocked(deps.connector.execute).mockResolvedValue(
      ok("/samples/test.pyc: python 3.9 byte-compiled")
    );
    const pyEnv = parseEnvelope(await handleSuggestTools(deps, { file: "test.pyc" }));
    expect(surfaces(pyEnv, "decompyle")).toBe(false);
    expect(surfaces(pyEnv, "pyinstaller-extractor")).toBe(false);

    // DOTNET — ilspy excluded (aliased to ilspycmd)
    vi.mocked(deps.connector.execute).mockResolvedValue(
      ok("/samples/test.exe: PE32 executable (console) Intel 80386 Mono/.Net assembly")
    );
    const dotnetEnv = parseEnvelope(await handleSuggestTools(deps, { file: "test.exe" }));
    expect(surfaces(dotnetEnv, "ilspy")).toBe(false);
  });

  it("has no duplicates within additional_tools", async () => {
    const deps = createMockDeps();
    vi.mocked(deps.connector.execute).mockResolvedValue(
      ok("/samples/test.exe: PE32 executable (GUI) Intel 80386")
    );

    const result = await handleSuggestTools(deps, { file: "test.exe" });
    const env = parseEnvelope(result);
    if (!env.data.additional_tools) return;

    const names = env.data.additional_tools.map((t: { name: string }) => t.name);
    expect(names.length).toBe(new Set(names).size);
  });

  it("omits additional_tools when catalog has no extras", async () => {
    const deps = createMockDeps();
    // Use a category unlikely to have catalog extras
    vi.mocked(deps.connector.execute).mockResolvedValue(
      ok("/samples/test.one: Microsoft OneNote")
    );

    const result = await handleSuggestTools(deps, { file: "test.one" });
    const env = parseEnvelope(result);
    expect(env.success).toBe(true);
    // OneNote has no catalog mapping, so additional_tools should be absent
    expect(env.data.additional_tools).toBeUndefined();
  });

  it("recommends r2ghidra for native PE at deep depth and teaches pdg in hints", async () => {
    const deps = createMockDeps();
    vi.mocked(deps.connector.execute).mockResolvedValue(
      ok("/samples/test.exe: PE32 executable (console) Intel 80386")
    );
    const result = await handleSuggestTools(deps, { file: "test.exe", depth: "deep" });
    const env = parseEnvelope(result);
    const r2g = env.data.recommended_tools.find((t: { name: string }) => t.name === "r2ghidra");
    expect(r2g).toBeDefined();
    expect(r2g.invocation).toContain("pdg @ entry0; pdg @ main");
    expect(env.data.analysis_hints).toContain("pdg @ main");
    expect(env.data.analysis_hints).toContain("afl");
  });

  it("does not recommend r2ghidra at standard depth but still teaches pdg in hints", async () => {
    const deps = createMockDeps();
    vi.mocked(deps.connector.execute).mockResolvedValue(
      ok("/samples/test.exe: PE32 executable (console) Intel 80386")
    );
    const result = await handleSuggestTools(deps, { file: "test.exe", depth: "standard" });
    const env = parseEnvelope(result);
    expect(env.data.recommended_tools.map((t: { name: string }) => t.name)).not.toContain("r2ghidra");
    expect(env.data.analysis_hints).toContain("pdg @ main");
  });
});
