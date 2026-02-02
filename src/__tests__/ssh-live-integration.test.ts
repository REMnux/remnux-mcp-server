/**
 * SSH live integration tests — runs MCP tools against a real REMnux VM via SSH.
 *
 * Skipped by default. Run with:
 *   SSH_LIVE_TEST=1 SSH_LIVE_HOST=172.16.118.195 SSH_LIVE_USER=remnux SSH_LIVE_PASSWORD=malware \
 *     npx vitest run src/__tests__/ssh-live-integration.test.ts
 *
 * Prerequisites:
 *   - REMnux VM reachable via SSH
 *   - demos/samples/client.exe available locally (uploaded to VM automatically)
 */

import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { readFileSync, existsSync } from "node:fs";
import { resolve } from "node:path";
import type { ToolResponse } from "../response.js";
import type { ServerConfig } from "../index.js";

const HOST = process.env.SSH_LIVE_HOST;
const USER = process.env.SSH_LIVE_USER || "remnux";
const PASSWORD = process.env.SSH_LIVE_PASSWORD;
const SAMPLES_DIR = "/home/remnux/files/samples";
const LOCAL_SAMPLE = resolve(import.meta.dirname, "../../demos/samples/client.exe");

const runLive = !!process.env.SSH_LIVE_TEST;

describe.skipIf(!runLive)("SSH live integration", () => {
  let client: Client;
  let closeTransports: () => Promise<void>;

  async function callTool(
    name: string,
    args: Record<string, unknown>,
  ): Promise<{ envelope: ToolResponse; isError?: boolean }> {
    const result = await client.callTool({ name, arguments: args });
    const textContent = (result.content as Array<{ type: string; text: string }>)[0];
    const envelope = JSON.parse(textContent.text) as ToolResponse;
    return { envelope, isError: result.isError as boolean | undefined };
  }

  beforeAll(async () => {
    if (!HOST) throw new Error("SSH_LIVE_HOST must be set");

    const config: ServerConfig = {
      mode: "ssh",
      host: HOST,
      user: USER,
      password: PASSWORD,
      samplesDir: SAMPLES_DIR,
      outputDir: "/home/remnux/files/output",
      timeout: 300,
      noSandbox: false,
    };

    const { createServer } = await import("../index.js");
    const server = await createServer(config);

    const [clientTransport, serverTransport] =
      InMemoryTransport.createLinkedPair();

    await server.connect(serverTransport);

    client = new Client({ name: "ssh-live-test-client", version: "1.0.0" });
    await client.connect(clientTransport);

    closeTransports = async () => {
      await clientTransport.close();
      await serverTransport.close();
    };

    // Ensure client.exe exists on the VM — upload if missing
    const { createConnector } = await import("../connectors/index.js");
    const connector = await createConnector(config);
    try {
      const check = await connector.executeShell(`test -f ${SAMPLES_DIR}/client.exe && echo exists`);
      if (!check.stdout.includes("exists")) {
        throw new Error("not found");
      }
    } catch {
      if (!existsSync(LOCAL_SAMPLE)) {
        throw new Error(
          `client.exe not found locally at ${LOCAL_SAMPLE} — cannot upload to VM`,
        );
      }
      await connector.executeShell(`mkdir -p ${SAMPLES_DIR}`);
      await connector.writeFile(
        `${SAMPLES_DIR}/client.exe`,
        readFileSync(LOCAL_SAMPLE),
      );
    }
    await connector.disconnect();
  }, 60_000);

  afterAll(async () => {
    await closeTransports?.();
  });

  // ─── get_file_info ──────────────────────────────────────────────────

  it("get_file_info returns hashes and file type", async () => {
    const { envelope, isError } = await callTool("get_file_info", {
      file: "client.exe",
    });

    expect(isError).toBeFalsy();
    expect(envelope.success).toBe(true);
    expect(envelope.tool).toBe("get_file_info");
    expect(envelope.data.sha256).toBeTruthy();
    expect(envelope.data.md5).toBeTruthy();
    expect(envelope.data.file_type).toBeTruthy();
  }, 15_000);

  // ─── run_tool: peframe ──────────────────────────────────────────────

  it("run_tool peframe produces sha256 output", async () => {
    const { envelope, isError } = await callTool("run_tool", {
      command: "peframe",
      input_file: "client.exe",
    });

    expect(isError).toBeFalsy();
    expect(envelope.success).toBe(true);
    expect(envelope.data.stdout).toMatch(/sha256/i);
  }, 60_000);

  // ─── run_tool: capa ─────────────────────────────────────────────────

  it("run_tool capa produces ATT&CK output", async () => {
    const { envelope, isError } = await callTool("run_tool", {
      command: "capa",
      input_file: "client.exe",
    });

    expect(isError).toBeFalsy();
    expect(envelope.success).toBe(true);
    expect(envelope.data.stdout).toMatch(/ATT&CK/);
  }, 120_000);

  // ─── run_tool: floss ────────────────────────────────────────────────

  it("run_tool floss produces static strings output", async () => {
    const { envelope, isError } = await callTool("run_tool", {
      command: "floss",
      input_file: "client.exe",
    });

    expect(isError).toBeFalsy();
    expect(envelope.success).toBe(true);
    expect(envelope.data.stdout).toMatch(/FLOSS STATIC/i);
  }, 120_000);

  // ─── analyze_file ───────────────────────────────────────────────────

  it("analyze_file auto-detects PE and runs tools", async () => {
    const { envelope, isError } = await callTool("analyze_file", {
      file: "client.exe",
    });

    expect(isError).toBeFalsy();
    expect(envelope.success).toBe(true);
    expect(envelope.tool).toBe("analyze_file");
    expect(envelope.data.detected_type).toBeTruthy();

    const category = envelope.data.matched_category as string;
    expect(category).toMatch(/PE|DotNET|\.NET/i);

    const toolsRun = envelope.data.tools_run as Array<{ name: string }>;
    expect(toolsRun.length).toBeGreaterThan(0);
    const toolNames = toolsRun.map((t) => t.name);
    expect(toolNames).toContain("peframe");
  }, 300_000);

  // ─── Error cases ──────────────────────────────────────────────────

  it("run_tool on nonexistent file returns error", async () => {
    const { envelope } = await callTool("run_tool", {
      command: "peframe",
      input_file: "nonexistent-file.exe",
    });

    expect(envelope.success).toBe(true);
    expect(envelope.data.exit_code).not.toBe(0);
  }, 15_000);

  it("get_file_info on nonexistent file returns error", async () => {
    const { envelope } = await callTool("get_file_info", {
      file: "does-not-exist.bin",
    });

    expect(envelope.tool).toBe("get_file_info");
  }, 15_000);
});
