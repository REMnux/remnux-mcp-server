import type { HandlerDeps } from "./types.js";
import { formatResponse } from "../response.js";

/**
 * get_server_info — report the MCP server version, how it reaches REMnux
 * (connector mode + transport), and the REMnux distro version on the target.
 *
 * The REMnux version is best-effort: `remnux version` (REMnux CLI) first, then
 * /etc/remnux-version. Any failure yields remnux_version: null rather than an
 * error, because the server-side facts are still useful for diagnostics.
 */
export async function handleGetServerInfo(deps: HandlerDeps, serverVersion: string) {
  const startTime = Date.now();
  const { connector, config } = deps;

  let remnuxVersion: string | null = null;
  try {
    const result = await connector.executeShell(
      "remnux version 2>/dev/null || cat /etc/remnux-version 2>/dev/null",
      { timeout: 10000 },
    );
    const firstLine = (result.stdout || "").trim().split("\n")[0]?.trim() ?? "";
    remnuxVersion = firstLine.length > 0 ? firstLine : null;
  } catch {
    remnuxVersion = null;
  }

  return formatResponse("get_server_info", {
    server_version: serverVersion,
    connector_mode: config.mode,
    transport: config.transport ?? "stdio",
    remnux_version: remnuxVersion,
  }, startTime);
}
