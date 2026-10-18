/**
 * Child-process tests for the HTTP-transport bind guard.
 *
 * The refusal lives in startHttpServer and calls process.exit(1), which a
 * same-process test cannot exercise without killing the test runner. So we
 * spawn the BUILT dist/cli.js and observe its real startup behavior. Skipped
 * automatically when dist/cli.js is absent (run `pnpm run build` first — the
 * verification flow builds before testing).
 */

import { describe, it, expect } from "vitest";
import { spawn, spawnSync, type ChildProcess } from "node:child_process";
import { request } from "node:http";
import { connect } from "node:net";
import { networkInterfaces } from "node:os";
import { fileURLToPath } from "node:url";
import { dirname, resolve } from "node:path";
import { existsSync } from "node:fs";

const here = dirname(fileURLToPath(import.meta.url));
const CLI = resolve(here, "../../dist/cli.js");
const hasBuild = existsSync(CLI);

// Empty MCP_TOKEN so a token in the ambient env can never leak into these cases.
const BASE_ENV = { ...process.env, MCP_TOKEN: "" };

/**
 * Spawn the CLI and resolve true if it is still running after a grace period
 * (i.e. it started and is listening), false if it exited on its own. Always
 * kills the child before resolving. Distinct ports avoid TIME_WAIT collisions.
 */
async function startsAndStaysUp(
  args: string[],
  env: Record<string, string> = {},
): Promise<boolean> {
  const child = spawn(process.execPath, [CLI, ...args], {
    env: { ...BASE_ENV, ...env },
    stdio: "ignore",
  });
  try {
    await new Promise((r) => setTimeout(r, 1500));
    return child.exitCode === null && child.signalCode === null;
  } finally {
    child.kill("SIGKILL");
  }
}

/**
 * POST an MCP initialize to /mcp with the given Host header and resolve the HTTP
 * status. A DNS-rebinding page reaches a loopback server with its own hostname in
 * the Host header, so `hostHeader` stands in for that attacker-controlled name.
 * Retries until the freshly spawned server is listening.
 */
async function statusForHostHeader(
  connectHost: string,
  port: number,
  hostHeader: string,
): Promise<number> {
  const body = JSON.stringify({
    jsonrpc: "2.0",
    id: 1,
    method: "initialize",
    params: {
      protocolVersion: "2025-03-26",
      capabilities: {},
      clientInfo: { name: "test-client", version: "1.0.0" },
    },
  });
  const once = () =>
    new Promise<number>((resolveStatus, reject) => {
      const req = request(
        {
          host: connectHost,
          port,
          path: "/mcp",
          method: "POST",
          headers: {
            Host: hostHeader,
            "Content-Type": "application/json",
            Accept: "application/json, text/event-stream",
            "Content-Length": Buffer.byteLength(body),
          },
        },
        (res) => {
          res.resume();
          resolveStatus(res.statusCode ?? 0);
        },
      );
      req.setTimeout(5000, () => req.destroy(new Error("request timed out")));
      req.on("error", reject);
      req.end(body);
    });
  for (let attempt = 0; ; attempt++) {
    try {
      return await once();
    } catch (err) {
      if (attempt >= 30) throw err;
      await new Promise((r) => setTimeout(r, 200));
    }
  }
}

/**
 * Spawn the CLI with the HTTP transport and resolve once that child reports it
 * is listening. Waiting on the child's own startup line, not on the port, keeps
 * an unrelated listener on the same port from answering in its place: a child
 * that fails to bind never prints it.
 */
async function spawnHttpServer(args: string[]): Promise<ChildProcess> {
  const child = spawn(process.execPath, [CLI, "--transport=http", ...args], {
    env: BASE_ENV,
    stdio: ["ignore", "ignore", "pipe"],
  });
  await new Promise<void>((resolveReady, reject) => {
    let stderr = "";
    const timer = setTimeout(() => {
      child.kill("SIGKILL");
      reject(new Error(`server did not start: ${stderr}`));
    }, 10_000);
    child.stderr!.on("data", (chunk: Buffer) => {
      stderr += chunk.toString();
      if (stderr.includes("REMnux MCP server started")) {
        clearTimeout(timer);
        resolveReady();
      }
    });
    child.once("exit", () => {
      clearTimeout(timer);
      reject(new Error(`server exited before starting: ${stderr}`));
    });
  });
  return child;
}

/**
 * Assert the spawned server is still running. A child that died on EADDRINUSE
 * would leave some other listener on the port to answer the probe.
 */
function expectRunning(child: ChildProcess) {
  expect(child.exitCode).toBeNull();
  expect(child.signalCode).toBeNull();
}

/** Resolve true if a TCP connection to host:port succeeds within 3 seconds. */
function tcpConnects(host: string, port: number): Promise<boolean> {
  return new Promise((resolveConnects) => {
    const socket = connect({ host, port });
    const done = (ok: boolean) => {
      socket.destroy();
      resolveConnects(ok);
    };
    socket.setTimeout(3000, () => done(false));
    socket.once("connect", () => done(true));
    socket.once("error", () => done(false));
  });
}

/** A non-loopback IPv4 address of this machine, or undefined when it has none. */
const externalIPv4 = Object.values(networkInterfaces())
  .flat()
  .find((a) => a && a.family === "IPv4" && !a.internal)?.address;

describe.skipIf(!hasBuild)("CLI HTTP DNS-rebinding protection", () => {
  // The MCP SDK enables Host-header validation on its own only for the exact
  // strings "127.0.0.1", "localhost", and "::1". The no-token bind check accepts
  // other loopback spellings too, so the server has to supply the allowed hosts
  // itself or those spellings run with no rebinding protection at all.
  it("rejects a foreign Host header on the default bind (control)", async () => {
    const child = await spawnHttpServer(["--http-port=39005"]);
    try {
      expect(await statusForHostHeader("127.0.0.1", 39005, "attacker.example")).toBe(403);
      expectRunning(child);
    } finally {
      child.kill("SIGKILL");
    }
  });

  it("rejects a foreign Host header on a LOCALHOST bind with no token", async () => {
    const child = await spawnHttpServer(["--http-host=LOCALHOST", "--http-port=39006"]);
    try {
      expect(await statusForHostHeader("localhost", 39006, "attacker.example")).toBe(403);
      expectRunning(child);
    } finally {
      child.kill("SIGKILL");
    }
  });

  it("still serves a loopback client on a LOCALHOST bind", async () => {
    const child = await spawnHttpServer(["--http-host=LOCALHOST", "--http-port=39007"]);
    try {
      expect(await statusForHostHeader("localhost", 39007, "localhost:39007")).toBe(200);
      expectRunning(child);
    } finally {
      child.kill("SIGKILL");
    }
  });
});

describe.skipIf(!hasBuild || !externalIPv4)("CLI HTTP empty --http-host", () => {
  // The bind check treats an empty host as the 127.0.0.1 default, but Node binds
  // an empty host string to every interface. The server has to bind what the
  // check approved, or an empty value opens an unauthenticated network listener.
  it("binds loopback only when --http-host is empty and no token is set", async () => {
    const child = await spawnHttpServer(["--http-host=", "--http-port=39008"]);
    try {
      expect(await statusForHostHeader("127.0.0.1", 39008, "localhost:39008")).toBe(200);
      expect(await tcpConnects(externalIPv4!, 39008)).toBe(false);
      expectRunning(child);
    } finally {
      child.kill("SIGKILL");
    }
  });

  it("reaches a wildcard listener through the external address (control)", async () => {
    const child = await spawnHttpServer([
      "--http-host=0.0.0.0",
      "--http-port=39009",
      "--insecure-no-auth",
    ]);
    try {
      expect(await statusForHostHeader("127.0.0.1", 39009, "localhost:39009")).toBe(200);
      expect(await tcpConnects(externalIPv4!, 39009)).toBe(true);
      expectRunning(child);
    } finally {
      child.kill("SIGKILL");
    }
  });
});

describe.skipIf(!hasBuild)("CLI HTTP bind guard", () => {
  it("refuses a non-loopback bind with no token", () => {
    const res = spawnSync(
      process.execPath,
      [CLI, "--transport=http", "--http-host=0.0.0.0", "--http-port=39001"],
      { encoding: "utf-8", timeout: 8000, env: BASE_ENV },
    );
    expect(res.status).toBe(1);
    expect(res.stderr).toMatch(/refus/i);
  });

  it("allows a non-loopback bind when a token is set", async () => {
    expect(
      await startsAndStaysUp(
        ["--transport=http", "--http-host=0.0.0.0", "--http-port=39002"],
        { MCP_TOKEN: "secret-token" },
      ),
    ).toBe(true);
  });

  it("allows a non-loopback bind with --insecure-no-auth", async () => {
    expect(
      await startsAndStaysUp([
        "--transport=http",
        "--http-host=0.0.0.0",
        "--http-port=39003",
        "--insecure-no-auth",
      ]),
    ).toBe(true);
  });

  it("allows the default loopback bind with no token (dev mode unchanged)", async () => {
    expect(
      await startsAndStaysUp(["--transport=http", "--http-port=39004"]),
    ).toBe(true);
  });
});
