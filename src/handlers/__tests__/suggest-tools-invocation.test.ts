import { describe, it, expect, vi } from "vitest";
import { handleSuggestTools } from "../suggest-tools.js";
import { createMockDeps, ok, parseEnvelope } from "./helpers.js";

describe("suggest_tools — invocation field", () => {
  async function recommend(fileOutput: string, file: string) {
    const deps = createMockDeps();
    vi.mocked(deps.connector.execute).mockResolvedValue(ok(fileOutput));
    // `which` availability check — return nothing; availability is orthogonal.
    vi.mocked(deps.connector.executeShell).mockResolvedValue(ok(""));
    const result = await handleSuggestTools(deps, { file });
    return parseEnvelope(result).data.recommended_tools as Array<{
      name: string;
      invocation: string;
      description: string;
      tier: string;
    }>;
  }

  it("surfaces a runnable invocation (with <file>, no /tmp) for every recommended tool", async () => {
    const tools = await recommend("/samples/a.pdf: PDF document, version 1.4", "a.pdf");
    expect(tools.length).toBeGreaterThan(0);
    for (const t of tools) {
      expect(t.invocation).toBeTruthy();
      expect(t.invocation).toContain("<file>");
      expect(t.invocation).not.toContain("/tmp");
    }
  });

  it("surfaces the .py binary, not the bare registry name", async () => {
    const tools = await recommend("/samples/a.pdf: PDF document, version 1.4", "a.pdf");
    const pdfid = tools.find((t) => t.name === "pdfid");
    expect(pdfid?.invocation).toBe("pdfid.py <file>");
  });

  it("keeps existing entry fields intact (additive change)", async () => {
    const tools = await recommend("/samples/a.pdf: PDF document, version 1.4", "a.pdf");
    expect(tools[0]).toHaveProperty("name");
    expect(tools[0]).toHaveProperty("description");
    expect(tools[0]).toHaveProperty("tier");
  });
});
