/**
 * Tests for the bundled get_osint_guidance tool.
 *
 * Uses InMemoryTransport to invoke through the MCP protocol, mirroring
 * report-tools.test.ts. The handler doesn't touch the connector, so only
 * createConnector needs mocking.
 */

import { describe, it, expect, vi, beforeAll, afterAll } from "vitest";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import type { Connector } from "../connectors/index.js";
import type { ServerConfig } from "../index.js";
import type { ToolResponse } from "../response.js";
import { loadOsintCatalogStrict } from "../osint/index.js";

const mockConnector = {
  execute: vi.fn(),
  executeShell: vi.fn(),
  writeFile: vi.fn(),
  writeFileFromPath: vi.fn(),
  readFileToPath: vi.fn(),
  disconnect: vi.fn(),
} satisfies Record<keyof Connector, ReturnType<typeof vi.fn>>;

vi.mock("../connectors/index.js", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../connectors/index.js")>();
  return {
    ...actual,
    createConnector: vi.fn().mockResolvedValue(mockConnector),
  };
});

const testConfig: ServerConfig = {
  mode: "docker",
  container: "test-remnux",
  samplesDir: "/home/remnux/files/samples",
  outputDir: "/home/remnux/files/output",
  timeout: 300,
  noSandbox: false,
};

let client: Client;
let closeTransports: () => Promise<void>;

beforeAll(async () => {
  const { createServer } = await import("../index.js");
  const server = await createServer(testConfig);

  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
  await server.connect(serverTransport);

  client = new Client({ name: "test-client", version: "1.0.0" });
  await client.connect(clientTransport);

  closeTransports = async () => {
    await clientTransport.close();
    await serverTransport.close();
  };
});

afterAll(async () => {
  await closeTransports?.();
});

async function callTool(
  name: string,
  args: Record<string, unknown>,
): Promise<{ envelope: ToolResponse; isError?: boolean }> {
  const result = await client.callTool({ name, arguments: args });
  const textContent = (result.content as Array<{ type: string; text: string }>)[0];
  const envelope = JSON.parse(textContent.text) as ToolResponse;
  return { envelope, isError: result.isError as boolean | undefined };
}

describe("get_osint_guidance", () => {
  it("returns full guidance + a CONDENSED catalog by default (topic='all')", async () => {
    const { envelope, isError } = await callTool("get_osint_guidance", {});

    expect(isError).toBeFalsy();
    expect(envelope.success).toBe(true);
    expect(envelope.tool).toBe("get_osint_guidance");
    expect(envelope.data.topic).toBe("all");

    // Persistent header + scope on every response.
    expect(envelope.data.header as string).toMatch(/Leads, not verdicts/i);
    expect(envelope.data.scope as string).toMatch(/triage/i);

    // Full guidance prose.
    expect(Array.isArray(envelope.data.tradecraft)).toBe(true);
    expect((envelope.data.tradecraft as unknown[]).length).toBeGreaterThanOrEqual(8);
    expect(envelope.data.workflow_by_ioc).toBeTruthy();
    expect(envelope.data.access_guidance).toBeTruthy();

    // Condensed catalog: present, but entries lack full-detail fields.
    const resources = envelope.data.resources as Array<Record<string, unknown>>;
    expect(Array.isArray(resources)).toBe(true);
    expect(resources.length).toBeGreaterThan(10);
    expect(resources[0]).toHaveProperty("name");
    expect(resources[0]).toHaveProperty("access");
    expect(resources[0]).toHaveProperty("content_disclosing");
    expect(resources[0]).not.toHaveProperty("url");
    expect(resources[0]).not.toHaveProperty("last_verified");
    expect(resources[0]).not.toHaveProperty("caveats");
    expect(envelope.data.resources_note as string).toMatch(/ioc_type/);
  });

  it("narrows to full-detail entries for a given ioc_type", async () => {
    const { envelope } = await callTool("get_osint_guidance", { ioc_type: "hash" });

    expect(envelope.data.ioc_type).toBe("hash");
    const resources = envelope.data.resources as Array<Record<string, unknown>>;
    expect(resources.length).toBeGreaterThan(0);
    // Full detail (not condensed).
    expect(resources[0]).toHaveProperty("url");
    expect(resources[0]).toHaveProperty("last_verified");
    expect(resources[0]).toHaveProperty("query_disclosing");
    // Every returned entry is relevant to the requested ioc_type.
    for (const r of resources) {
      expect((r.ioc_types as string[])).toContain("hash");
    }
  });

  it("orders keyless (api_nokey) services first within a slice", async () => {
    const { envelope } = await callTool("get_osint_guidance", { ioc_type: "ip" });
    const resources = envelope.data.resources as Array<{ ai_access: string }>;
    expect(resources[0].ai_access).toBe("api_nokey");
    const firstWeb = resources.findIndex((r) => r.ai_access === "web");
    const lastNoKey = resources.map((r) => r.ai_access).lastIndexOf("api_nokey");
    if (firstWeb !== -1) expect(lastNoKey).toBeLessThan(firstWeb);
  });

  it("returns a non-empty slice for every ioc_type (including host_artifact)", async () => {
    for (const t of ["hash", "url", "domain", "ip", "family", "host_artifact"]) {
      const { envelope } = await callTool("get_osint_guidance", { ioc_type: t });
      const resources = envelope.data.resources as unknown[];
      expect(Array.isArray(resources)).toBe(true);
      expect(resources.length, `ioc_type=${t}`).toBeGreaterThan(0);
    }
  });

  it("returns prose only (no resources) for a prose topic without ioc_type", async () => {
    const { envelope } = await callTool("get_osint_guidance", { topic: "tradecraft" });

    expect(envelope.data.topic).toBe("tradecraft");
    expect(envelope.data.header).toBeTruthy();
    expect(Array.isArray(envelope.data.tradecraft)).toBe(true);
    expect(envelope.data.resources).toBeUndefined();
    expect(envelope.data.workflow_by_ioc).toBeUndefined();
  });

  it("returns the full catalog for topic='resources'", async () => {
    const { envelope } = await callTool("get_osint_guidance", { topic: "resources" });

    const resources = envelope.data.resources as Array<Record<string, unknown>>;
    const expected = loadOsintCatalogStrict().resources.length;
    expect(resources.length).toBe(expected);
    // Full detail, and no guidance prose.
    expect(resources[0]).toHaveProperty("last_verified");
    expect(envelope.data.tradecraft).toBeUndefined();
  });

  it("returns ioc_type-filtered full detail even when topic='all'", async () => {
    const { envelope } = await callTool("get_osint_guidance", { topic: "all", ioc_type: "ip" });
    const resources = envelope.data.resources as Array<Record<string, unknown>>;
    expect(resources.length).toBeGreaterThan(0);
    expect(resources[0]).toHaveProperty("last_verified"); // full detail wins over condensed
    for (const r of resources) expect((r.ioc_types as string[])).toContain("ip");
  });
});

describe("get_osint_guidance is registered", () => {
  it("lists the tool", async () => {
    const { tools } = await client.listTools();
    const names = tools.map((t) => t.name);
    expect(names).toContain("get_osint_guidance");
  });
});
