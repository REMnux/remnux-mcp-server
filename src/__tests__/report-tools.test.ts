/**
 * Tests for the bundled report tools + resources (get_report_template,
 * get_report_guidance, remnux://report/*).
 *
 * Uses InMemoryTransport to invoke through the MCP protocol, mirroring
 * tool-handlers.test.ts, so the tools/resources are tested as wired in
 * createServer(). The report handlers don't touch the connector, so only
 * createConnector needs mocking.
 */

import { describe, it, expect, vi, beforeAll, afterAll } from "vitest";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import type { Connector } from "../connectors/index.js";
import type { ServerConfig } from "../index.js";
import type { ToolResponse } from "../response.js";
import { GUIDELINES_DIGEST, REPORT_TEMPLATE } from "../report/content.generated.js";
import { OPTIONAL_SECTION_CONVENTION } from "../report/optional-sections.js";

const ARTICLE_URL = "https://zeltser.com/malware-analysis-report";

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

describe("get_report_template", () => {
  it("returns the bundled template with CC BY 4.0 attribution", async () => {
    const { envelope, isError } = await callTool("get_report_template", {});

    expect(isError).toBeFalsy();
    expect(envelope.success).toBe(true);
    expect(envelope.tool).toBe("get_report_template");

    const template = envelope.data.template as string;
    expect(typeof template).toBe("string");
    expect(template).toContain("Creative Commons Attribution 4.0");
    expect(template).toContain("## Executive Summary");

    expect(envelope.data.attribution as string).toContain("CC BY 4.0");
    expect((envelope.data.source as { fallbackArticleUrl: string }).fallbackArticleUrl).toBe(ARTICLE_URL);
    expect(envelope.data.guidelines).toBeUndefined();
  });

  it("carries the optional-section convention so (Optional) is not copied into headings", async () => {
    const { envelope } = await callTool("get_report_template", {});

    const convention = envelope.data.optional_section_convention as Record<string, unknown>;
    expect(convention).toBeTruthy();
    expect(convention.version).toBe("1.0.0");
    expect(convention.title as string).toMatch(/optional/i);

    // The instruction must name the marker and show the stripped heading form.
    const serialized = JSON.stringify(convention);
    expect(serialized).toContain("(Optional)");
    expect(serialized).toContain("Detection Engineering");
    expect(serialized).toContain("#detection-engineering");
  });
});

describe("get_report_guidance", () => {
  it("returns the full digest by default", async () => {
    const { envelope, isError } = await callTool("get_report_guidance", {});

    expect(isError).toBeFalsy();
    expect(envelope.success).toBe(true);
    expect(envelope.data.topic).toBe("all");

    const guidelines = envelope.data.guidelines as Record<string, unknown>;
    expect(guidelines).toHaveProperty("longReportSections");
    expect(guidelines).toHaveProperty("antiPatterns");
    expect(guidelines).toHaveProperty("confidence");
    // Website/MCP plumbing keys must be stripped from the bundled digest.
    expect(guidelines).not.toHaveProperty("mcp");
    expect(guidelines).not.toHaveProperty("crossServerHandoffs");

    expect(envelope.data.attribution as string).toContain("Lenny Zeltser");
    expect(envelope.data.notes as string).toMatch(/malware_review_report|rating_score_writing/);
  });

  it("narrows to a single topic", async () => {
    const { envelope } = await callTool("get_report_guidance", { topic: "anti_patterns" });

    expect(envelope.data.topic).toBe("anti_patterns");
    const guidelines = envelope.data.guidelines as Record<string, unknown>;
    expect(guidelines).toHaveProperty("antiPatterns");
    expect(guidelines).not.toHaveProperty("longReportSections");
  });

  it("carries the optional-section convention for the full digest and a narrowed topic", async () => {
    for (const topic of [undefined, "sections"]) {
      const { envelope } = await callTool("get_report_guidance", topic ? { topic } : {});
      const convention = envelope.data.optional_section_convention as Record<string, unknown>;
      expect(convention, `topic=${topic ?? "all"}`).toBeTruthy();
      expect(convention.version).toBe("1.0.0");
    }
  });

  it("returns the server-authored triage checklist for topic='triage_checklist'", async () => {
    const { envelope, isError } = await callTool("get_report_guidance", { topic: "triage_checklist" });

    expect(isError).toBeFalsy();
    expect(envelope.data.topic).toBe("triage_checklist");

    const td = envelope.data.triage_discipline as Record<string, unknown>;
    expect(td).toBeTruthy();
    expect(td.version).toBe("1.0.0");
    expect(Array.isArray(td.before_claiming_a_behavior)).toBe(true);
    expect((td.core_principle as string).toLowerCase()).toContain("artifact");

    // It is NOT the synced report-writing digest, and carries its own provenance note.
    expect(envelope.data.guidelines).toBeUndefined();
    expect(envelope.data.attribution).toBeUndefined();
    expect(envelope.data.optional_section_convention).toBeUndefined();
    expect(envelope.data.notes as string).toMatch(/offline|server-authored/i);
  });
});

describe("report tools + resources are registered", () => {
  it("lists both report tools", async () => {
    const { tools } = await client.listTools();
    const names = tools.map((t) => t.name);
    expect(names).toContain("get_report_template");
    expect(names).toContain("get_report_guidance");
  });

  it("lists the report resources, including the optional-section convention", async () => {
    const { resources } = await client.listResources();
    const uris = resources.map((r) => r.uri);
    expect(uris).toContain("remnux://report/template");
    expect(uris).toContain("remnux://report/guidelines");
    expect(uris).toContain("remnux://report/optional-section-convention");
  });
});

describe("report resource bodies carry the optional-section convention", () => {
  async function readResourceJson(uri: string): Promise<Record<string, unknown>> {
    const result = await client.readResource({ uri });
    const first = (result.contents as Array<{ text: string }>)[0];
    return JSON.parse(first.text) as Record<string, unknown>;
  }

  it("embeds the convention in the guidelines resource JSON", async () => {
    const body = await readResourceJson("remnux://report/guidelines");
    expect(body).toHaveProperty("guidelines");
    const convention = body.optional_section_convention as Record<string, unknown>;
    expect(convention).toBeTruthy();
    expect(convention.version).toBe("1.0.0");
  });

  it("serves the convention as its own resource", async () => {
    const convention = await readResourceJson("remnux://report/optional-section-convention");
    expect(convention.version).toBe("1.0.0");
    expect(convention.title as string).toMatch(/optional/i);
    expect(Array.isArray(convention.applies_to)).toBe(true);
  });
});

describe("optional-section convention stays in sync with the bundled template", () => {
  it("names exactly the template's (Optional) headings (drift guard)", () => {
    // The template is synced from zeltser.com; the convention is authored here. If an
    // optional section is renamed/added/removed upstream, this fails instead of silently
    // going stale (sync:report-guidance --check does not compare against this file).
    const templateHeadings = [...REPORT_TEMPLATE.matchAll(/^## (.+ \(Optional\))$/gm)].map((m) => m[1]);
    const conventionIds = OPTIONAL_SECTION_CONVENTION.applies_to.map((s) => s.identifier);

    expect(templateHeadings.length).toBeGreaterThan(0);
    expect([...templateHeadings].sort()).toEqual([...conventionIds].sort());
  });

  it("names exactly the digest's (Optional) section identifiers (digest drift guard)", () => {
    // The digest (situationalSections, longReportSections, reviewCriteriaSectionMap) references these
    // sections by their "(Optional)"-suffixed identifiers. The convention's cross-walk depends on that
    // fidelity, so assert both sides agree — a template-only guard would miss a digest-side rename.
    const found = new Set<string>();
    const walk = (v: unknown): void => {
      if (typeof v === "string") {
        if (/ \(Optional\)$/.test(v)) found.add(v);
      } else if (Array.isArray(v)) {
        v.forEach(walk);
      } else if (v && typeof v === "object") {
        Object.values(v).forEach(walk);
      }
    };
    walk(GUIDELINES_DIGEST);
    const conventionIds = OPTIONAL_SECTION_CONVENTION.applies_to.map((s) => s.identifier);

    expect(found.size).toBeGreaterThan(0);
    expect([...found].sort()).toEqual([...conventionIds].sort());
  });
});

describe("bundled digest size backstop", () => {
  it("stays within a sane bound (catches accidental double-embedding, not normal growth)", () => {
    const bytes = Buffer.byteLength(JSON.stringify(GUIDELINES_DIGEST), "utf-8");
    expect(bytes).toBeGreaterThan(10_000); // non-trivial content is present
    expect(bytes).toBeLessThan(160_000); // ~2x the measured ~77KB
  });
});
