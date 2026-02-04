import { describe, it, expect, vi } from "vitest";
import { handleCheckTools } from "../check-tools.js";
import { createMockDeps, ok, parseEnvelope } from "./helpers.js";

describe("handleCheckTools", () => {
  it("returns summary with available and missing tools", async () => {
    const deps = createMockDeps();
    const execShell = vi.mocked(deps.connector.executeShell);

    // Specific tools are "available", rest "missing"
    const availableTools = new Set(["strings", "exiftool", "capa"]);

    execShell.mockImplementation(async (cmd) => {
      // Connectivity probe
      if (cmd === "true") return ok("");
      // Batched which commands - return paths for available tools
      if (cmd.includes("which ")) {
        const paths = [...availableTools].map((t) => `/usr/bin/${t}`).join("\n");
        return ok(paths);
      }
      return ok("");
    });

    const result = await handleCheckTools(deps);
    const env = parseEnvelope(result);

    expect(env.success).toBe(true);
    expect(env.data.summary.total).toBeGreaterThan(0);
    expect(env.data.summary.available).toBe(3);
    expect(env.data.summary.missing).toBe(env.data.summary.total - 3);
    expect(env.data.tools).toBeDefined();
    expect(Array.isArray(env.data.tools)).toBe(true);
  });

  it("returns connection error when container is not running", async () => {
    const deps = createMockDeps();
    vi.mocked(deps.connector.executeShell).mockRejectedValue(new Error("not running"));

    const result = await handleCheckTools(deps);
    const env = parseEnvelope(result);

    // Connectivity probe fails before checking individual tools
    expect(env.success).toBe(false);
  });

  it("marks all tools as unavailable when only which calls throw", async () => {
    const deps = createMockDeps();
    vi.mocked(deps.connector.executeShell).mockImplementation(async (cmd) => {
      // Connectivity probe succeeds
      if (cmd === "true") return { stdout: "", stderr: "", exitCode: 0 };
      // Batched which calls fail
      throw new Error("which failed");
    });

    const result = await handleCheckTools(deps);
    const env = parseEnvelope(result);

    expect(env.success).toBe(true);
    expect(env.data.summary.available).toBe(0);
    expect(env.data.summary.missing).toBe(env.data.summary.total);
  });

  it("handles mixed available and missing tools", async () => {
    const deps = createMockDeps();
    vi.mocked(deps.connector.executeShell).mockImplementation(async (cmd) => {
      if (cmd === "true") return ok("");
      // Only strings is available
      if (cmd.includes("which ")) {
        return ok("/usr/bin/strings");
      }
      return ok("");
    });

    const result = await handleCheckTools(deps);
    const env = parseEnvelope(result);

    expect(env.success).toBe(true);
    const stringsEntry = env.data.tools.find((t: { tool: string }) => t.tool === "strings");
    expect(stringsEntry).toBeDefined();
    expect(stringsEntry.available).toBe(true);
    expect(stringsEntry.path).toBe("/usr/bin/strings");
  });
});
