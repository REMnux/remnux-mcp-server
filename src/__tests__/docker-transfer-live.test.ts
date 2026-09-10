/**
 * Live functional tests for the three Docker file-transfer paths — the code
 * changed to remediate GHSA-qp43-2vqh-w88w.
 *
 * The unit suite (docker-cp-argv.test.ts) pins the invariant that no shell is
 * involved. This suite proves the transfers still actually work end to end
 * against a real container, including for filenames that a shell would have
 * mangled, and that the bytes that arrive are the bytes that left.
 *
 * Skipped by default. Run with:
 *   LIVE_TEST=1 CONTAINER=remnux-distro pnpm exec vitest run \
 *     src/__tests__/docker-transfer-live.test.ts
 *
 * Isolation: the server under test is pointed at scratch directories under
 * /tmp inside the container, never at an analyst's real samples/output dirs,
 * and every host artifact lives in a mkdtemp directory. Teardown removes only
 * what this suite created.
 */

import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { execFileSync } from "node:child_process";
import { mkdtempSync, writeFileSync, readFileSync, rmSync, existsSync, readdirSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createHash } from "node:crypto";
import type { ToolResponse } from "../response.js";
import type { ServerConfig } from "../index.js";

const CONTAINER = process.env.CONTAINER ?? "remnux";
const runLive = !!process.env.LIVE_TEST;

// Scratch roots inside the container. Distinct from the REMnux defaults so a
// real analyst workspace is never read, written, or cleaned up by this suite.
const RUN_ID = `mcp-live-${Date.now()}`;
const C_SAMPLES = `/tmp/${RUN_ID}/samples`;
const C_OUTPUT = `/tmp/${RUN_ID}/output`;

// A filename carrying the cmd.exe metacharacters that can actually appear in a
// real filename on Windows (`< > : " / \ | ? *` cannot), plus a space and the
// single quote the removed escaper keyed on. Restricted to that set deliberately:
// this file lands on the host, so a name with `>` in it could never be created on
// Windows — and Windows is the only platform the vulnerability fires on, so a
// fixture that cannot exist there would make the test unrunnable where it matters.
const NASTY_NAME = `rep ort&echo PWNED&dir %USERNAME%^(x)!d!;$(id)\`id\`'.bin`;
const NASTY_CONTENT = "argv-boundary-holds\n";

function dockerExec(args: string[]): string {
  return execFileSync("docker", ["exec", CONTAINER, ...args], {
    encoding: "utf-8",
    stdio: ["ignore", "pipe", "pipe"],
  });
}

function sha256(buf: Buffer | string): string {
  return createHash("sha256").update(buf).digest("hex");
}

describe.skipIf(!runLive)("docker transfer paths (live)", () => {
  let client: Client;
  let closeTransports: (() => Promise<void>) | undefined;
  let hostDir: string;
  let unsandboxedClient: Client;
  let closeUnsandboxed: (() => Promise<void>) | undefined;

  async function connect(config: ServerConfig, name: string) {
    const { createServer } = await import("../index.js");
    const server = await createServer(config);
    const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
    await server.connect(serverTransport);
    const c = new Client({ name, version: "1.0.0" });
    await c.connect(clientTransport);
    return {
      client: c,
      close: async () => {
        await clientTransport.close();
        await serverTransport.close();
      },
    };
  }

  async function call(
    c: Client,
    name: string,
    args: Record<string, unknown>,
  ): Promise<ToolResponse> {
    const result = await c.callTool({ name, arguments: args });
    const text = (result.content as Array<{ type: string; text: string }>)[0];
    return JSON.parse(text.text) as ToolResponse;
  }

  beforeAll(async () => {
    const running = execFileSync(
      "docker",
      ["inspect", "--format", "{{.State.Running}}", CONTAINER],
      { encoding: "utf-8" },
    ).trim();
    if (running !== "true") {
      throw new Error(`Container "${CONTAINER}" must be running.`);
    }

    dockerExec(["mkdir", "-p", C_SAMPLES, C_OUTPUT]);
    hostDir = mkdtempSync(join(tmpdir(), "mcp-transfer-live-"));

    const base: ServerConfig = {
      mode: "docker",
      container: CONTAINER,
      samplesDir: C_SAMPLES,
      outputDir: C_OUTPUT,
      timeout: 300,
      noSandbox: false,
    };

    // Sandboxed server. In docker mode --sandbox requires an explicit host-side
    // --ingest-root (index.ts refuses to start without one), because the default
    // would be the container's samples dir, which no host path can ever be under.
    ({ client, close: closeTransports } = await connect(
      { ...base, ingestRoot: hostDir },
      "transfer-live",
    ));

    // Unsandboxed server: the documented default (cli.ts sets noSandbox: true).
    // Required for the hostile-filename case, because isPathSafe rejects `&`
    // before it would ever reach the connector.
    ({ client: unsandboxedClient, close: closeUnsandboxed } = await connect(
      { ...base, noSandbox: true },
      "transfer-live-unsandboxed",
    ));
  }, 60_000);

  afterAll(async () => {
    // Failure-safe: every step is independently guarded so one failure cannot
    // strand container or host artifacts.
    try {
      await closeTransports?.();
    } catch { /* ignore */ }
    try {
      await closeUnsandboxed?.();
    } catch { /* ignore */ }
    try {
      dockerExec(["rm", "-rf", `/tmp/${RUN_ID}`]);
    } catch { /* ignore */ }
    try {
      if (hostDir) rmSync(hostDir, { recursive: true, force: true });
    } catch { /* ignore */ }
  }, 30_000);

  // ─── writeFileFromPath: upload_from_host ────────────────────────────

  it("upload_from_host transfers host bytes into the container intact", async () => {
    const content = "upload-roundtrip-payload\n";
    const hostFile = join(hostDir, "upload me.bin");
    writeFileSync(hostFile, content);

    const envelope = await call(client, "upload_from_host", {
      host_path: hostFile,
      filename: "uploaded.bin",
    });

    expect(envelope.success).toBe(true);
    expect(envelope.data.sha256).toBe(sha256(content));

    const inContainer = dockerExec(["sha256sum", `${C_SAMPLES}/uploaded.bin`]);
    expect(inContainer.split(/\s+/)[0]).toBe(sha256(content));
  }, 60_000);

  // ─── readFileToPath: download_file ──────────────────────────────────

  it("download_file with archive:false returns the exact bytes", async () => {
    const content = "download-raw-payload\n";
    dockerExec(["bash", "-c", `printf '%s' '${content}' > ${C_OUTPUT}/raw.bin`]);

    const envelope = await call(client, "download_file", {
      file_path: "raw.bin",
      output_path: hostDir,
      archive: false,
    });

    expect(envelope.success).toBe(true);
    expect(envelope.data.archived).toBe(false);
    const landed = readFileSync(envelope.data.host_path as string);
    expect(landed.toString()).toBe(content);
    expect(sha256(landed)).toBe(envelope.data.sha256);
  }, 60_000);

  it("download_file default path produces a password-protected archive of the file", async () => {
    const content = "download-archived-payload\n";
    dockerExec(["bash", "-c", `printf '%s' '${content}' > ${C_OUTPUT}/archived.bin`]);

    const envelope = await call(client, "download_file", {
      file_path: "archived.bin",
      output_path: hostDir,
    });

    expect(envelope.success).toBe(true);
    expect(envelope.data.archived).toBe(true);
    expect(envelope.data.archive_password).toBe("infected");

    const archivePath = envelope.data.host_path as string;
    expect(existsSync(archivePath)).toBe(true);

    // Verify the contents, not just that a file landed.
    const extracted = execFileSync(
      "unzip",
      ["-p", "-P", "infected", archivePath, "archived.bin"],
      { encoding: "utf-8" },
    );
    expect(extracted).toBe(content);

    // Extracting with a password does not by itself prove the archive IS
    // encrypted — an unencrypted zip extracts fine with a password supplied.
    // Prove the encryption by showing the wrong password fails.
    expect(() =>
      execFileSync("unzip", ["-p", "-P", "wrong-password", archivePath, "archived.bin"], {
        stdio: ["ignore", "pipe", "pipe"],
      }),
    ).toThrow();
  }, 60_000);

  // ─── the regression this whole change is about ──────────────────────

  it("download_file handles a filename full of cmd.exe metacharacters, with no injection", async () => {
    // Scope, stated honestly: this is a FUNCTIONAL regression test, not the
    // security proof. On POSIX the old single-quote-escaped implementation was
    // correct, so this case would have passed before the fix too. What it
    // establishes is that removing the shell did not break transfers of awkward
    // filenames. The security invariant is pinned platform-independently in
    // docker-cp-argv.test.ts.
    //
    // Anti-vacuity: if the fixture name ever loses its teeth, this test would
    // pass while proving nothing.
    for (const ch of ["&", "%", "^", "(", ")", "!", ";", "$", "`", "'", " "]) {
      expect(NASTY_NAME).toContain(ch);
    }

    // Create the file inside the container without any shell quoting of our own
    // (base64 the name so no layer has to escape it).
    const nameB64 = Buffer.from(NASTY_NAME, "utf-8").toString("base64");
    const contentB64 = Buffer.from(NASTY_CONTENT, "utf-8").toString("base64");
    dockerExec([
      "python3",
      "-c",
      `import base64,os;n=base64.b64decode("${nameB64}").decode();` +
        `open(os.path.join("${C_OUTPUT}",n),"wb").write(base64.b64decode("${contentB64}"))`,
    ]);

    const hostFilesBefore = new Set(readdirSync(hostDir));

    const envelope = await call(unsandboxedClient, "download_file", {
      file_path: NASTY_NAME,
      output_path: hostDir,
      archive: false,
    });

    expect(envelope.success).toBe(true);

    // The bytes arrived, under the full hostile name, on the host.
    const landed = readFileSync(envelope.data.host_path as string);
    expect(landed.toString()).toBe(NASTY_CONTENT);
    expect(envelope.data.host_path).toBe(join(hostDir, NASTY_NAME));

    // Exactly one new file in the download directory — the embedded `&echo`,
    // `$(id)` and `%USERNAME%` produced no extra artifact there. This checks the
    // two directories a shell would most plausibly have written into; it is not
    // a claim that nothing happened anywhere on the machine.
    const added = readdirSync(hostDir).filter((f) => !hostFilesBefore.has(f));
    expect(added).toEqual([NASTY_NAME]);
    expect(readdirSync(process.cwd())).not.toContain("PWNED");
  }, 60_000);

  it("upload_from_host still refuses a hostile target filename (validator unchanged)", async () => {
    const hostFile = join(hostDir, "benign.bin");
    writeFileSync(hostFile, "x");

    const envelope = await call(client, "upload_from_host", {
      host_path: hostFile,
      filename: "a&b.bin",
    });

    expect(envelope.success).toBe(false);
  }, 30_000);

  // ─── writeFile: output spilling ─────────────────────────────────────

  it("oversized run_tool output spills to the container output dir via writeFile", async () => {
    const envelope = await call(client, "run_tool", {
      command: `python3 -c "print('A'*200000)"`,
    });

    expect(envelope.success).toBe(true);
    expect(envelope.data.truncated).toBe(true);

    const saved = envelope.data.stdout_saved_file as string;
    expect(saved).toBeTruthy();

    // The spill went through DockerConnector.writeFile — confirm the file is
    // really in the container and holds the exact expected bytes, not merely
    // "something big". stdout is trimmed before spilling, so the trailing
    // newline from print() is gone and the content is exactly 200000 'A's.
    const expected = "A".repeat(200_000);
    const digest = dockerExec(["sha256sum", `${C_OUTPUT}/${saved}`]).split(/\s+/)[0];
    expect(digest).toBe(sha256(expected));
  }, 120_000);
});
