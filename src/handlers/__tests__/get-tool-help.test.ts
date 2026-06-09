import { describe, it, expect, vi } from "vitest";
import { handleGetToolHelp } from "../get-tool-help.js";
import { createMockDeps, ok, parseEnvelope } from "./helpers.js";

describe("handleGetToolHelp — name resolution", () => {
  it("resolves a .py registry name to its real executable", async () => {
    const deps = createMockDeps();
    vi.mocked(deps.connector.execute).mockResolvedValue(ok("emldump help text"));
    await handleGetToolHelp(deps, { tool: "emldump" });
    expect(deps.connector.execute).toHaveBeenCalledWith(
      ["emldump.py", "--help"],
      expect.anything(),
    );
  });

  it("resolves a pseudo-tool alias to its base binary", async () => {
    const deps = createMockDeps();
    vi.mocked(deps.connector.execute).mockResolvedValue(ok("vol3 help text"));
    await handleGetToolHelp(deps, { tool: "vol3-pslist" });
    expect(deps.connector.execute).toHaveBeenCalledWith(
      ["vol3", "--help"],
      expect.anything(),
    );
  });

  it("passes an unknown tool name through unchanged", async () => {
    const deps = createMockDeps();
    vi.mocked(deps.connector.execute).mockResolvedValue(ok("file help text"));
    await handleGetToolHelp(deps, { tool: "file" });
    expect(deps.connector.execute).toHaveBeenCalledWith(
      ["file", "--help"],
      expect.anything(),
    );
  });

  it("rejects invalid tool names before any resolution or execution", async () => {
    const deps = createMockDeps();
    const result = await handleGetToolHelp(deps, { tool: "olevba -a" });
    const env = parseEnvelope(result);
    expect(env.success).toBe(false);
    expect(deps.connector.execute).not.toHaveBeenCalled();
  });

  it("includes the canonical invocation for a resolved registry tool", async () => {
    const deps = createMockDeps();
    vi.mocked(deps.connector.execute).mockResolvedValue(ok("help text"));
    const result = await handleGetToolHelp(deps, { tool: "vol3-pslist" });
    const env = parseEnvelope(result);
    expect(env.data.invocation).toBe("vol3 -f <file> windows.pslist");
  });

  it("omits invocation for an unknown (non-registry) tool", async () => {
    const deps = createMockDeps();
    vi.mocked(deps.connector.execute).mockResolvedValue(ok("help text"));
    const result = await handleGetToolHelp(deps, { tool: "file" });
    const env = parseEnvelope(result);
    expect(env.data.invocation).toBeUndefined();
  });
});
