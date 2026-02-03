import { describe, it, expect, vi, beforeEach } from "vitest";
import { handleExtractIOCs } from "../extract-iocs.js";
import { createMockDeps, parseEnvelope } from "./helpers.js";

// Mock the extractor module
vi.mock("../../ioc/extractor.js", () => ({
  extractIOCs: vi.fn(),
}));

import { extractIOCs } from "../../ioc/extractor.js";

// Type cast for bun compatibility (vi.mocked not available in bun's test runner)
const mockedExtractIOCs = extractIOCs as ReturnType<typeof vi.fn>;

describe("handleExtractIOCs", () => {
  beforeEach(() => {
    mockedExtractIOCs.mockReset();
  });

  it("excludes noise by default", async () => {
    const deps = createMockDeps();
    mockedExtractIOCs.mockReturnValue({
      iocs: [{ type: "ipv4", value: "10.0.0.1", confidence: 0.9 }],
      noise: [{ type: "ipv4", value: "127.0.0.1", confidence: 0.1 }],
      summary: { total: 1, noise_filtered: 1, by_type: { ipv4: 1 } },
    });

    const result = await handleExtractIOCs(deps, {
      text: "found 10.0.0.1",
      include_noise: false,
      include_private_ips: false,
    });

    const env = parseEnvelope(result);
    expect(env.data.noise).toBeUndefined();
    expect(env.data.iocs).toHaveLength(1);
  });

  it("includes noise when include_noise is true", async () => {
    const deps = createMockDeps();
    mockedExtractIOCs.mockReturnValue({
      iocs: [],
      noise: [{ type: "ipv4", value: "127.0.0.1", confidence: 0.1 }],
      summary: { total: 0, noise_filtered: 1, by_type: {} },
    });

    const result = await handleExtractIOCs(deps, {
      text: "found 127.0.0.1",
      include_noise: true,
      include_private_ips: false,
    });

    const env = parseEnvelope(result);
    expect(env.data.noise).toBeDefined();
    expect(env.data.noise).toHaveLength(1);
  });

  it("wraps errors thrown by extractIOCs", async () => {
    const deps = createMockDeps();
    mockedExtractIOCs.mockImplementation(() => {
      throw new Error("parser crash");
    });

    const result = await handleExtractIOCs(deps, {
      text: "some text",
      include_noise: false,
      include_private_ips: false,
    });

    const env = parseEnvelope(result);
    expect(env.success).toBe(false);
    expect(result.isError).toBe(true);
  });

  it("returns summary statistics from extractor", async () => {
    const deps = createMockDeps();
    mockedExtractIOCs.mockReturnValue({
      iocs: [
        { type: "domain", value: "evil.com", confidence: 0.9 },
        { type: "ipv4", value: "192.168.1.1", confidence: 0.8 },
      ],
      noise: [],
      summary: { total: 2, noise_filtered: 0, by_type: { domain: 1, ipv4: 1 } },
    });

    const result = await handleExtractIOCs(deps, {
      text: "evil.com 192.168.1.1",
      include_noise: false,
      include_private_ips: false,
    });

    const env = parseEnvelope(result);
    expect(env.data.summary.total).toBe(2);
    expect(env.data.summary.by_type).toEqual({ domain: 1, ipv4: 1 });
  });
});
