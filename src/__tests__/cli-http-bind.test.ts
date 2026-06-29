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
import { spawn, spawnSync } from "node:child_process";
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
