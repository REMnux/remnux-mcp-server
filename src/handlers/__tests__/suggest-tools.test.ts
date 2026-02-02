import { describe, it, expect, vi } from "vitest";
import { handleSuggestTools } from "../suggest-tools.js";
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
});
