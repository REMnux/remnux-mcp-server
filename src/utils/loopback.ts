/**
 * Loopback-host detection for the HTTP transport security gate.
 *
 * The HTTP transport refuses to start when bound to a non-loopback address
 * without an auth token (see startHttpServer). These helpers decide whether a
 * bind host counts as loopback and whether a token is therefore required.
 *
 * Container/VM isolation remains the security boundary; this gate only closes
 * the one path that escapes it — an unauthenticated, network-reachable bind.
 */

/**
 * Return true if `host` is a loopback bind address (traffic cannot leave the
 * machine). Covers IPv4 127.0.0.0/8, IPv6 ::1, the "localhost" hostname, and
 * IPv4-mapped IPv6 loopback (::ffff:127.x.x.x). An empty/undefined host is
 * treated as loopback because the transport defaults to 127.0.0.1.
 *
 * Intentionally inclusive: when in doubt it favors "loopback" (no refusal),
 * because --insecure-no-auth is the explicit escape hatch for anything this
 * does not recognize, so a deliberate operator is never locked out.
 */
export function isLoopbackHost(host: string | undefined): boolean {
  if (!host) return true; // transport default is 127.0.0.1
  // Lowercase and strip surrounding brackets the way a bind addr may appear ([::1]).
  const h = host.trim().toLowerCase().replace(/^\[+|\]+$/g, "");
  if (h === "" || h === "localhost" || h === "::1") return true;
  // Unwrap IPv4-mapped IPv6 loopback (::ffff:127.0.0.1) to its v4 form.
  const v4 = h.startsWith("::ffff:") ? h.slice("::ffff:".length) : h;
  // IPv4 loopback range 127.0.0.0/8.
  if (/^127\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(v4)) return true;
  return false;
}

/**
 * Host-header names to accept on a loopback bind, or undefined for a
 * non-loopback bind. These are the DNS-rebinding defense for a loopback server
 * running without a token.
 *
 * The MCP SDK's createMcpExpressApp turns on Host-header validation by itself
 * only when the bind host is exactly "127.0.0.1", "localhost", or "::1".
 * isLoopbackHost accepts more spellings than that (LOCALHOST, 127.0.0.2,
 * ::ffff:127.0.0.1), so without an explicit list those binds start with no
 * token and no rebinding protection. The list holds the SDK's own defaults plus
 * the configured host in the form the SDK compares against: the hostname a URL
 * parse produces, lowercased, with IPv6 in brackets.
 */
export function loopbackAllowedHosts(host: string | undefined): string[] | undefined {
  if (!isLoopbackHost(host)) return undefined;
  const allowed = ["localhost", "127.0.0.1", "[::1]"];
  const h = (host ?? "").trim().replace(/^\[+|\]+$/g, "");
  if (h) {
    try {
      const hostname = new URL(`http://${h.includes(":") ? `[${h}]` : h}`).hostname;
      if (!allowed.includes(hostname)) allowed.push(hostname);
    } catch {
      // An unparseable host cannot appear in a Host header either; the defaults suffice.
    }
  }
  return allowed;
}

/**
 * Return true if the HTTP transport must refuse to start: a non-loopback bind
 * with no auth token and no explicit insecure override. Pure so it can be
 * unit-tested without spawning a server or calling process.exit.
 */
export function httpBindRequiresToken(
  host: string | undefined,
  token: string | undefined,
  allowInsecure: boolean | undefined,
): boolean {
  return !token && !allowInsecure && !isLoopbackHost(host);
}
