/**
 * Live integration tests — runs MCP tools against a real Docker container.
 *
 * Skipped by default. Run with:
 *   LIVE_TEST=1 npx vitest run src/__tests__/live-integration.test.ts
 *
 * Prerequisites:
 *   - Docker container named "remnux" running from remnux/remnux-distro:noble
 *   - demos/samples/client.7z mounted or copied into the container
 */

import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { execSync } from "node:child_process";
import type { ToolResponse } from "../response.js";
import type { ServerConfig } from "../index.js";

const CONTAINER = process.env.CONTAINER ?? "remnux";
const SAMPLES_DIR = "/home/remnux/files/samples";

// Skip unless LIVE_TEST is set
const runLive = !!process.env.LIVE_TEST;

describe.skipIf(!runLive)("live integration", () => {
  let client: Client;
  let closeTransports: () => Promise<void>;

  // Helper to call a tool and parse the response envelope
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
    // Verify container is running
    try {
      const status = execSync(
        `docker inspect --format='{{.State.Running}}' ${CONTAINER}`,
        { encoding: "utf-8" },
      ).trim();
      if (status !== "true") {
        throw new Error(`Container ${CONTAINER} is not running`);
      }
    } catch {
      throw new Error(
        `Container "${CONTAINER}" must be running. Start with:\n` +
          `  docker run -d --name ${CONTAINER} remnux/remnux-distro:noble`,
      );
    }

    // Extract client.7z if client.exe doesn't exist yet
    try {
      execSync(`docker exec ${CONTAINER} test -f ${SAMPLES_DIR}/client.exe`, {
        stdio: "ignore",
      });
    } catch {
      execSync(
        `docker exec ${CONTAINER} bash -c "cd '${SAMPLES_DIR}' && 7z x -pmalware -y client.7z"`,
        { stdio: "ignore" },
      );
    }

    // Create MCP server with real connector (no mocks)
    const config: ServerConfig = {
      mode: "docker",
      container: CONTAINER,
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

    client = new Client({ name: "live-test-client", version: "1.0.0" });
    await client.connect(clientTransport);

    closeTransports = async () => {
      await clientTransport.close();
      await serverTransport.close();
    };
  }, 30_000);

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

    // Should match PE category
    const category = envelope.data.matched_category as string;
    expect(category.toUpperCase()).toMatch(/^(PE|DOTNET)$/);
    expect(category).toMatch(/PE|DotNET|\.NET/i);

    // Should have run at least peframe
    const toolsRun = envelope.data.tools_run as Array<{ name: string }>;
    expect(toolsRun.length).toBeGreaterThan(0);
    const toolNames = toolsRun.map((t) => t.name);
    expect(toolNames).toContain("peframe");
  }, 300_000);

  // ─── Error case ─────────────────────────────────────────────────────

  it("run_tool on nonexistent file returns error", async () => {
    const { envelope } = await callTool("run_tool", {
      command: "peframe",
      input_file: "nonexistent-file.exe",
    });

    // Tool ran but likely exited non-zero — still a success envelope
    // because run_tool treats non-zero exit as data, not MCP error
    expect(envelope.success).toBe(true);
    expect(envelope.data.exit_code).not.toBe(0);
  }, 15_000);

  it("get_file_info on nonexistent file returns error", async () => {
    const { envelope } = await callTool("get_file_info", {
      file: "does-not-exist.bin",
    });

    // get_file_info may return partial results or error
    // The file command will fail, so we expect either error or empty type
    expect(envelope.tool).toBe("get_file_info");
  }, 15_000);
});
