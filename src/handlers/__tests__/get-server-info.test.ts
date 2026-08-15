import { describe, it, expect, vi } from "vitest";
import { handleGetServerInfo } from "../get-server-info.js";
import { createMockDeps, ok, parseEnvelope } from "./helpers.js";

describe("handleGetServerInfo", () => {
  it("reports server version, connector mode, and the REMnux version from the target", async () => {
    const deps = createMockDeps({ mode: "docker", transport: "stdio" });
    vi.mocked(deps.connector.executeShell).mockImplementation(async (cmd) => {
      if (cmd.includes("remnux-version") || cmd.includes("remnux version")) return ok("7.0.9\n");
      return ok("");
    });

    const env = parseEnvelope(await handleGetServerInfo(deps, "0.1.66"));

    expect(env.success).toBe(true);
    expect(env.tool).toBe("get_server_info");
    expect(env.data.server_version).toBe("0.1.66");
    expect(env.data.connector_mode).toBe("docker");
    expect(env.data.transport).toBe("stdio");
    expect(env.data.remnux_version).toBe("7.0.9");
  });

  it("still succeeds with remnux_version null when the target cannot report a version", async () => {
    const deps = createMockDeps({ mode: "local" });
    vi.mocked(deps.connector.executeShell).mockRejectedValue(new Error("not running"));

    const env = parseEnvelope(await handleGetServerInfo(deps, "0.1.66"));

    expect(env.success).toBe(true);
    expect(env.data.server_version).toBe("0.1.66");
    expect(env.data.connector_mode).toBe("local");
    expect(env.data.remnux_version).toBeNull();
  });
});
