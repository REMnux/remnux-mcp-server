import type { HandlerDeps } from "./types.js";
import { formatResponse } from "../response.js";

/**
 * get_server_info — report the MCP server version, how it reaches REMnux
 * (connector mode + transport), and the REMnux distro version on the target.
 *
 * The REMnux version is best-effort. /etc/remnux-version is the authoritative
 * source (the distro's own CLI reads it); `remnux version` is only a fallback,
 * and its output can carry banner or help text ahead of the version, so each
 * source is scanned for a bare version line or a "remnux-version X" line rather
 * than trusting the first line. Any failure or non-version output yields remnux_version: null
 * rather than an error, because the server-side facts are still useful.
 */
// A line that IS a version ("7.0.9"), or the CLI's "remnux-version 7.0.9" line.
// Anything else (banners, help text, the CLI's own version) is not the distro version.
const BARE_VERSION_LINE = /^v?(\d+(?:\.\d+)+)$/;
const LABELED_VERSION_LINE = /\bremnux-version\s*[:=]?\s*v?(\d+(?:\.\d+)+)\b/i;

function extractVersion(stdout: string): string | null {
  for (const raw of (stdout || "").split("\n")) {
    const line = raw.trim();
    const m = line.match(BARE_VERSION_LINE) ?? line.match(LABELED_VERSION_LINE);
    if (m) return m[1];
  }
  return null;
}

async function readRemnuxVersion(deps: HandlerDeps): Promise<string | null> {
  const probes = ["cat /etc/remnux-version 2>/dev/null", "remnux version 2>/dev/null"];
  for (const cmd of probes) {
    try {
      const result = await deps.connector.executeShell(cmd, { timeout: 10000 });
      const version = extractVersion(result.stdout);
      if (version) return version;
    } catch {
      // try the next source
    }
  }
  return null;
}

export async function handleGetServerInfo(deps: HandlerDeps, serverVersion: string) {
  const startTime = Date.now();
  const { config } = deps;

  const remnuxVersion = await readRemnuxVersion(deps);

  return formatResponse("get_server_info", {
    server_version: serverVersion,
    connector_mode: config.mode,
    transport: config.transport ?? "stdio",
    remnux_version: remnuxVersion,
  }, startTime);
}
