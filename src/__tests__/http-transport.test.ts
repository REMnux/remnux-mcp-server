import { describe, it, expect, afterEach } from "vitest";
import type { Server } from "node:http";
import { randomUUID } from "node:crypto";
import { gzipSync } from "node:zlib";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { createServer, createHttpApp } from "../index.js";

const TEST_TOKEN = "test-token-123";

const MCP_HEADERS = {
  "Content-Type": "application/json",
  "Accept": "application/json, text/event-stream",
};

async function parseResponse(res: Response) {
  const contentType = res.headers.get("content-type") ?? "";
  if (contentType.includes("text/event-stream")) {
    // Parse SSE: extract JSON from "data: " lines
    const text = await res.text();
    const dataLines = text.split("\n").filter(l => l.startsWith("data: "));
    const results = dataLines.map(l => JSON.parse(l.slice(6)));
    return results.length === 1 ? results[0] : results;
  }
  return res.json();
}

function makeConfig() {
  return {
    mode: "local" as const,
    samplesDir: "/tmp/samples",
    outputDir: "/tmp/output",
    timeout: 30,
    noSandbox: true,
  };
}

function createTestApp(options: { token?: string } = {}) {
  // Use the production app, middleware order and verifier included, not a copy:
  // a duplicated setup here cannot catch a defect in the real one.
  const app = createHttpApp("127.0.0.1", options.token);

  const sessions = new Map<string, StreamableHTTPServerTransport>();
  const config = makeConfig();

  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  app.all("/mcp", async (req: any, res: any) => {
    const sessionId = req.headers["mcp-session-id"] as string | undefined;

    if (sessionId && sessions.has(sessionId)) {
      const transport = sessions.get(sessionId)!;
      await transport.handleRequest(req, res, req.body);
      return;
    }

    const transport = new StreamableHTTPServerTransport({
      sessionIdGenerator: () => randomUUID(),
    });

    transport.onclose = () => {
      if (transport.sessionId) sessions.delete(transport.sessionId);
    };

    const server = await createServer(config);
    await server.connect(transport);
    await transport.handleRequest(req, res, req.body);

    if (transport.sessionId) {
      sessions.set(transport.sessionId, transport);
    }
  });

  return app;
}

function listenOnFreePort(app: ReturnType<typeof createHttpApp>): Promise<{ server: Server; port: number }> {
  return new Promise((resolve) => {
    const server = app.listen(0, "127.0.0.1", () => {
      const addr = server.address();
      const port = typeof addr === "object" && addr ? addr.port : 0;
      resolve({ server, port });
    });
  });
}

function mcpUrl(port: number) {
  return `http://127.0.0.1:${port}/mcp`;
}

function initRequest(id: number = 1) {
  return {
    jsonrpc: "2.0",
    id,
    method: "initialize",
    params: {
      protocolVersion: "2025-03-26",
      capabilities: {},
      clientInfo: { name: "test-client", version: "1.0.0" },
    },
  };
}

describe("HTTP Transport", () => {
  let server: Server | null = null;

  afterEach(() => {
    if (server) {
      server.close();
      server = null;
    }
  });

  it("rejects unauthenticated request when token configured", async () => {
    const app = createTestApp({ token: TEST_TOKEN });
    const result = await listenOnFreePort(app);
    server = result.server;

    const res = await fetch(mcpUrl(result.port), {
      method: "POST",
      headers: MCP_HEADERS,
      body: JSON.stringify(initRequest()),
    });

    expect(res.status).toBe(401);
  });

  it("rejects an incorrect bearer token with 401, not 500", async () => {
    const app = createTestApp({ token: TEST_TOKEN });
    const result = await listenOnFreePort(app);
    server = result.server;

    const res = await fetch(mcpUrl(result.port), {
      method: "POST",
      headers: { ...MCP_HEADERS, "Authorization": "Bearer wrong-token-entirely" },
      body: JSON.stringify(initRequest()),
    });

    // A bare Error from the verifier surfaces as 500 (server fault) instead of
    // 401 (auth failure), because requireBearerAuth maps only InvalidTokenError
    // to 401. Guard the status explicitly.
    expect(res.status).toBe(401);
  });

  it("rejects a same-length incorrect bearer token with 401", async () => {
    const app = createTestApp({ token: TEST_TOKEN });
    const result = await listenOnFreePort(app);
    server = result.server;

    // Same length as TEST_TOKEN, so this exercises the timingSafeEqual branch
    // rather than the length short-circuit.
    const sameLength = "x".repeat(TEST_TOKEN.length);
    expect(sameLength.length).toBe(TEST_TOKEN.length);

    const res = await fetch(mcpUrl(result.port), {
      method: "POST",
      headers: { ...MCP_HEADERS, "Authorization": `Bearer ${sameLength}` },
      body: JSON.stringify(initRequest()),
    });

    expect(res.status).toBe(401);
  });

  // The token check must run before body parsing, so body-parser reads only
  // requests with a valid token. These tests send a body that cannot parse.
  // With parsing first the server answers 400, and with the token check first
  // it answers 401.
  it("checks the token before it parses the body", async () => {
    const app = createTestApp({ token: TEST_TOKEN });
    const result = await listenOnFreePort(app);
    server = result.server;

    const res = await fetch(mcpUrl(result.port), {
      method: "POST",
      headers: MCP_HEADERS,
      body: "{not json",
    });

    expect(res.status).toBe(401);
  });

  it("checks the token before it decompresses the body", async () => {
    const app = createTestApp({ token: TEST_TOKEN });
    const result = await listenOnFreePort(app);
    server = result.server;

    // One valid gzip frame followed by bytes that are not gzip, the shape of
    // GHSA-27r3-jxmh-p828. Decompressing it fails, so a server that parses
    // first answers 400.
    const body = Buffer.concat([gzipSync(JSON.stringify(initRequest())), Buffer.from("TRAILING-GARBAGE")]);
    const res = await fetch(mcpUrl(result.port), {
      method: "POST",
      headers: { ...MCP_HEADERS, "Content-Encoding": "gzip" },
      body,
    });

    expect(res.status).toBe(401);
  });

  it("does not parse the body of an unauthenticated request to another path", async () => {
    const app = createTestApp({ token: TEST_TOKEN });
    const result = await listenOnFreePort(app);
    server = result.server;

    // The token check covers /mcp only, so a parser on every path would answer
    // this with 400 before the missing route answers 404.
    const res = await fetch(`http://127.0.0.1:${result.port}/other`, {
      method: "POST",
      headers: MCP_HEADERS,
      body: "{not json",
    });

    expect(res.status).toBe(404);
  });

  it("still parses the body after a valid token (control)", async () => {
    const app = createTestApp({ token: TEST_TOKEN });
    const result = await listenOnFreePort(app);
    server = result.server;

    const res = await fetch(mcpUrl(result.port), {
      method: "POST",
      headers: { ...MCP_HEADERS, "Authorization": `Bearer ${TEST_TOKEN}` },
      body: "{not json",
    });

    expect(res.status).toBe(400);
  });

  it("accepts valid bearer token", async () => {
    const app = createTestApp({ token: TEST_TOKEN });
    const result = await listenOnFreePort(app);
    server = result.server;

    const res = await fetch(mcpUrl(result.port), {
      method: "POST",
      headers: {
        ...MCP_HEADERS,
        "Authorization": `Bearer ${TEST_TOKEN}`,
      },
      body: JSON.stringify(initRequest()),
    });

    expect(res.status).toBe(200);
    const body = await parseResponse(res) as { result: { serverInfo: { name: string } } };
    expect(body.result.serverInfo.name).toBe("remnux-mcp-server");
  });

  it("works without token when none configured (dev mode)", async () => {
    const app = createTestApp(); // no token
    const result = await listenOnFreePort(app);
    server = result.server;

    const res = await fetch(mcpUrl(result.port), {
      method: "POST",
      headers: MCP_HEADERS,
      body: JSON.stringify(initRequest()),
    });

    expect(res.status).toBe(200);
    const body = await parseResponse(res) as { result: { serverInfo: { name: string } } };
    expect(body.result.serverInfo.name).toBe("remnux-mcp-server");
  });

  it("completes MCP initialize + tool list via HTTP", async () => {
    const app = createTestApp();
    const result = await listenOnFreePort(app);
    server = result.server;

    // Step 1: Initialize
    const initRes = await fetch(mcpUrl(result.port), {
      method: "POST",
      headers: MCP_HEADERS,
      body: JSON.stringify(initRequest()),
    });

    expect(initRes.status).toBe(200);
    const sessionId = initRes.headers.get("mcp-session-id");
    expect(sessionId).toBeTruthy();

    // Step 2: Send initialized notification + list tools in same request
    const listToolsRes = await fetch(mcpUrl(result.port), {
      method: "POST",
      headers: {
        ...MCP_HEADERS,
        "mcp-session-id": sessionId!,
      },
      body: JSON.stringify([
        { jsonrpc: "2.0", method: "notifications/initialized" },
        { jsonrpc: "2.0", id: 2, method: "tools/list", params: {} },
      ]),
    });

    expect(listToolsRes.status).toBe(200);
    const toolsBody = await parseResponse(listToolsRes) as Array<{ id?: number; result: { tools: Array<{ name: string }> } }> | { id?: number; result: { tools: Array<{ name: string }> } };
    // Response to batched request - find the tools/list response
    const toolsResponse = Array.isArray(toolsBody) ? toolsBody.find((r) => r.id === 2) : toolsBody;
    expect(toolsResponse!.result.tools.length).toBeGreaterThan(0);

    const toolNames = toolsResponse!.result.tools.map((t) => t.name);
    expect(toolNames).toContain("run_tool");
    expect(toolNames).toContain("analyze_file");
  });

  it("rejects invalid session ID with 404", async () => {
    const app = createTestApp();
    const result = await listenOnFreePort(app);
    server = result.server;

    const res = await fetch(mcpUrl(result.port), {
      method: "POST",
      headers: {
        ...MCP_HEADERS,
        "mcp-session-id": "nonexistent-session",
      },
      body: JSON.stringify({
        jsonrpc: "2.0",
        id: 1,
        method: "tools/list",
        params: {},
      }),
    });

    // SDK returns 400 or 404 for non-init requests with invalid/missing session
    expect([400, 404]).toContain(res.status);
  });
});
