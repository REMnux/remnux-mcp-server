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
      // Each entry should have required fields
      for (const tool of env.data.additional_tools) {
        expect(tool).toHaveProperty("command");
        expect(tool).toHaveProperty("name");
        expect(tool).toHaveProperty("description");
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
    const additionalCommands = (env.data.additional_tools ?? []).map((t: { command: string }) => t.command);

    // No normalized overlap between registry commands and additional_tools
    for (const cmd of additionalCommands) {
      expect(registryCommands.has(normalize(cmd))).toBe(false);
    }
  });

  it("excludes catalog entries aliased to registry tools", async () => {
    const deps = createMockDeps();

    // PE file — readpe-formerly-pev should be excluded (aliased to pescan/pestr)
    vi.mocked(deps.connector.execute).mockResolvedValue(
      ok("/samples/test.exe: PE32 executable (GUI) Intel 80386")
    );
    const pe = await handleSuggestTools(deps, { file: "test.exe" });
    const peEnv = parseEnvelope(pe);
    const peAdditional = (peEnv.data.additional_tools ?? []).map((t: { command: string }) => t.command);
    // Precondition: catalog must contain the aliased tool for the negative assertion to be meaningful
    const peCatalog = toolCatalog.forMcpCategory("PE").map((t) => t.command);
    expect(peCatalog).toContain("readpe-formerly-pev");
    expect(peAdditional).not.toContain("readpe-formerly-pev");

    // PDF file — origamindee, pdftk-java should be excluded at standard depth;
    // peepdf-3 should be excluded at deep depth (where peepdf enters the registry)
    vi.mocked(deps.connector.execute).mockResolvedValue(
      ok("/samples/doc.pdf: PDF document, version 1.4")
    );
    const pdf = await handleSuggestTools(deps, { file: "doc.pdf" });
    const pdfEnv = parseEnvelope(pdf);
    const pdfAdditional = (pdfEnv.data.additional_tools ?? []).map((t: { command: string }) => t.command);
    // Precondition: catalog must contain the aliased tools
    const pdfCatalog = toolCatalog.forMcpCategory("PDF").map((t) => t.command);
    expect(pdfCatalog).toContain("origamindee");
    expect(pdfCatalog).toContain("pdftk-java");
    expect(pdfAdditional).not.toContain("origamindee");
    expect(pdfAdditional).not.toContain("pdftk-java");
    // peepdf-3 should still appear at standard depth (peepdf is deep-tier only)
    expect(pdfAdditional).toContain("peepdf-3");

    // At deep depth, peepdf enters registry so peepdf-3 alias kicks in
    const pdfDeep = await handleSuggestTools(deps, { file: "doc.pdf", depth: "deep" });
    const pdfDeepEnv = parseEnvelope(pdfDeep);
    const pdfDeepAdditional = (pdfDeepEnv.data.additional_tools ?? []).map((t: { command: string }) => t.command);
    expect(pdfDeepAdditional).not.toContain("peepdf-3");

    // OLE2 file — oletools, xlmmacrodeobfuscator should be excluded
    vi.mocked(deps.connector.execute).mockResolvedValue(
      ok("/samples/doc.doc: Composite Document File V2 Document")
    );
    const ole = await handleSuggestTools(deps, { file: "doc.doc" });
    const oleEnv = parseEnvelope(ole);
    const oleAdditional = (oleEnv.data.additional_tools ?? []).map((t: { command: string }) => t.command);
    // Precondition: catalog must contain the aliased tools
    const oleCatalog = toolCatalog.forMcpCategory("OLE2").map((t) => t.command);
    expect(oleCatalog).toContain("oletools");
    expect(oleCatalog).toContain("xlmmacrodeobfuscator");
    expect(oleAdditional).not.toContain("oletools");
    expect(oleAdditional).not.toContain("xlmmacrodeobfuscator");

    // Python file — decompyle and pyinstaller-extractor should be excluded (aliased)
    vi.mocked(deps.connector.execute).mockResolvedValue(
      ok("/samples/test.pyc: python 3.9 byte-compiled")
    );
    const py = await handleSuggestTools(deps, { file: "test.pyc" });
    const pyEnv = parseEnvelope(py);
    const pyAdditional = (pyEnv.data.additional_tools ?? []).map((t: { command: string }) => t.command);
    expect(pyAdditional).not.toContain("decompyle");
    expect(pyAdditional).not.toContain("pyinstaller-extractor");

    // DOTNET file — ilspy should be excluded (aliased to ilspycmd)
    vi.mocked(deps.connector.execute).mockResolvedValue(
      ok("/samples/test.exe: PE32 executable (console) Intel 80386 Mono/.Net assembly")
    );
    const dotnet = await handleSuggestTools(deps, { file: "test.exe" });
    const dotnetEnv = parseEnvelope(dotnet);
    const dotnetAdditional = (dotnetEnv.data.additional_tools ?? []).map((t: { command: string }) => t.command);
    expect(dotnetAdditional).not.toContain("ilspy");
  });

  it("has no duplicates within additional_tools", async () => {
    const deps = createMockDeps();
    vi.mocked(deps.connector.execute).mockResolvedValue(
      ok("/samples/test.exe: PE32 executable (GUI) Intel 80386")
    );

    const result = await handleSuggestTools(deps, { file: "test.exe" });
    const env = parseEnvelope(result);
    if (!env.data.additional_tools) return;

    const commands = env.data.additional_tools.map((t: { command: string }) => t.command);
    expect(commands.length).toBe(new Set(commands).size);
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
});
