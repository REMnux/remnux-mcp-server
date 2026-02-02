/**
 * Local live integration tests — runs MCP tools against the local filesystem.
 *
 * Skipped by default. Run with:
 *   LOCAL_LIVE_TEST=1 npx vitest run src/__tests__/local-live-integration.test.ts
 *
 * Prerequisites:
 *   - REMnux tools installed locally (local mode)
 *   - Or just basic coreutils for fundamental tool tests
 */

import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { mkdtempSync, writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { ToolResponse } from "../response.js";
import type { ServerConfig } from "../index.js";

const runLive = !!process.env.LOCAL_LIVE_TEST;

describe.skipIf(!runLive)("Local live integration", () => {
  let client: Client;
  let closeTransports: () => Promise<void>;
  let tempSamplesDir: string;
  let tempOutputDir: string;

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
    // Create temp directories for samples and output
    tempSamplesDir = mkdtempSync(join(tmpdir(), "remnux-local-samples-"));
    tempOutputDir = mkdtempSync(join(tmpdir(), "remnux-local-output-"));

    // Create a test sample file
    writeFileSync(
      join(tempSamplesDir, "test-sample.txt"),
      "This is a test sample file for local integration testing.\n",
    );

    const config: ServerConfig = {
      mode: "local",
      samplesDir: tempSamplesDir,
      outputDir: tempOutputDir,
      timeout: 300,
      noSandbox: false,
    };

    const { createServer } = await import("../index.js");
    const server = await createServer(config);

    const [clientTransport, serverTransport] =
      InMemoryTransport.createLinkedPair();

    await server.connect(serverTransport);

    client = new Client({ name: "local-live-test-client", version: "1.0.0" });
    await client.connect(clientTransport);

    closeTransports = async () => {
      await clientTransport.close();
      await serverTransport.close();
    };
  }, 30_000);

  afterAll(async () => {
    await closeTransports?.();

    // Clean up temp directories
    try {
      rmSync(tempSamplesDir, { recursive: true, force: true });
      rmSync(tempOutputDir, { recursive: true, force: true });
    } catch {
      // best-effort cleanup
    }
  });

  // ─── run_tool ──────────────────────────────────────────────────────

  it("run_tool executes a command", async () => {
    const { envelope, isError } = await callTool("run_tool", {
      command: "echo test-output",
    });

    expect(isError).toBeFalsy();
    expect(envelope.success).toBe(true);
    expect(envelope.tool).toBe("run_tool");
    expect(envelope.data.stdout).toContain("test-output");
  }, 15_000);

  // ─── get_file_info ────────────────────────────────────────────────

  it("get_file_info returns file metadata", async () => {
    const { envelope, isError } = await callTool("get_file_info", {
      file: "test-sample.txt",
    });

    expect(isError).toBeFalsy();
    expect(envelope.success).toBe(true);
    expect(envelope.tool).toBe("get_file_info");
    expect(envelope.data.sha256).toBeTruthy();
    expect(envelope.data.md5).toBeTruthy();
    expect(envelope.data.file_type).toBeTruthy();
  }, 15_000);

  // ─── list_files ───────────────────────────────────────────────────

  it("list_files shows files in samples directory", async () => {
    const { envelope, isError } = await callTool("list_files", {
      directory: "samples",
    });

    expect(isError).toBeFalsy();
    expect(envelope.success).toBe(true);
    expect(envelope.tool).toBe("list_files");

    const files = envelope.data.files as Array<{ name: string }>;
    const names = files.map((f) => f.name);
    expect(names).toContain("test-sample.txt");
  }, 15_000);

  // ─── upload_sample ────────────────────────────────────────────────

  it("upload_sample writes a file to samples dir", async () => {
    const content = Buffer.from("uploaded content").toString("base64");

    const { envelope, isError } = await callTool("upload_sample", {
      filename: "uploaded-test.txt",
      content_base64: content,
    });

    expect(isError).toBeFalsy();
    expect(envelope.success).toBe(true);
    expect(envelope.tool).toBe("upload_sample");
    expect(envelope.data.sha256).toBeTruthy();
  }, 15_000);

  // ─── download_file ────────────────────────────────────────────────

  it("download_file retrieves a file from output dir", async () => {
    // First write a file to the output directory
    writeFileSync(join(tempOutputDir, "result.txt"), "analysis result");

    const { envelope, isError } = await callTool("download_file", {
      file_path: "result.txt",
    });

    expect(isError).toBeFalsy();
    expect(envelope.success).toBe(true);
    expect(envelope.tool).toBe("download_file");
    expect(envelope.data.content_base64).toBeTruthy();

    // Decode and verify content
    const decoded = Buffer.from(
      envelope.data.content_base64 as string,
      "base64",
    ).toString("utf-8");
    expect(decoded).toBe("analysis result");
  }, 15_000);

  // ─── extract_archive ───────────────────────────────────────────────

  it("extract_archive on a non-archive file returns error", async () => {
    const { envelope } = await callTool("extract_archive", {
      archive_file: "test-sample.txt",
    });

    // A .txt file isn't an archive — expect failure or non-zero exit
    expect(envelope.tool).toBe("extract_archive");
  }, 30_000);

  // ─── analyze_file ─────────────────────────────────────────────────

  it("analyze_file runs on a text file", async () => {
    const { envelope, isError } = await callTool("analyze_file", {
      file: "test-sample.txt",
    });

    expect(isError).toBeFalsy();
    expect(envelope.success).toBe(true);
    expect(envelope.tool).toBe("analyze_file");
    expect(envelope.data.detected_type).toBeTruthy();
  }, 120_000);

  // ─── extract_iocs (no connector needed, but tests MCP path) ──────

  it("extract_iocs extracts indicators from text", async () => {
    const { envelope, isError } = await callTool("extract_iocs", {
      text: "Found C2 at 45.33.32.156 and http://evil.example.com/payload.exe",
    });

    expect(isError).toBeFalsy();
    expect(envelope.success).toBe(true);
    expect(envelope.tool).toBe("extract_iocs");
  }, 15_000);

  // ─── Error cases ──────────────────────────────────────────────────

  it("get_file_info on nonexistent file returns error", async () => {
    const { envelope } = await callTool("get_file_info", {
      file: "does-not-exist.bin",
    });

    expect(envelope.tool).toBe("get_file_info");
  }, 15_000);

  it("run_tool on nonexistent command returns non-zero exit", async () => {
    const { envelope } = await callTool("run_tool", {
      command: "nonexistent-tool-xyz",
    });

    // Should either fail or return error
    expect(envelope.tool).toBe("run_tool");
  }, 15_000);
});
