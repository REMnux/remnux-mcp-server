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

  it("prefers /etc/remnux-version and never reports CLI banner text as the version", async () => {
    const deps = createMockDeps({ mode: "docker" });
    vi.mocked(deps.connector.executeShell).mockImplementation(async (cmd) => {
      // A `remnux version` CLI that prints a banner first must not win over the file.
      if (cmd.startsWith("cat /etc/remnux-version")) return ok("7.0.9\n");
      if (cmd.startsWith("remnux version")) return ok("REMnux CLI 2.1\nremnux-version 7.0.9\n");
      return ok("");
    });

    const env = parseEnvelope(await handleGetServerInfo(deps, "0.1.66"));
    expect(env.data.remnux_version).toBe("7.0.9");
  });

  it("falls back to `remnux version` and reads the distro version, not the CLI's own banner version", async () => {
    const deps = createMockDeps({ mode: "docker" });
    vi.mocked(deps.connector.executeShell).mockImplementation(async (cmd) => {
      if (cmd.startsWith("cat /etc/remnux-version")) return ok("", 1);
      if (cmd.startsWith("remnux version")) return ok("REMnux CLI 2.1\nremnux-version 7.0.9\n");
      return ok("");
    });

    const env = parseEnvelope(await handleGetServerInfo(deps, "0.1.66"));
    expect(env.data.remnux_version).toBe("7.0.9");
  });

  it("reports null when the only output is non-version text (help/banner/error on stdout)", async () => {
    const deps = createMockDeps({ mode: "docker" });
    vi.mocked(deps.connector.executeShell).mockResolvedValue(ok("Usage: remnux <command>\n", 0));

    const env = parseEnvelope(await handleGetServerInfo(deps, "0.1.66"));
    expect(env.success).toBe(true);
    expect(env.data.remnux_version).toBeNull();
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
