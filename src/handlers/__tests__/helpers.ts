import { vi } from "vitest";
import type { HandlerDeps } from "../types.js";
import { SessionState } from "../../state/session.js";

export function createMockDeps(overrides?: Partial<HandlerDeps["config"]>): HandlerDeps {
  return {
    connector: {
      execute: vi.fn(),
      executeShell: vi.fn(),
      writeFile: vi.fn(),
      writeFileFromPath: vi.fn(),
      readFileToPath: vi.fn(),
      disconnect: vi.fn(),
    },
    config: {
      samplesDir: "/samples",
      outputDir: "/output",
      timeout: 300,
      noSandbox: false,
      mode: "docker" as const,
      ...overrides,
    },
    sessionState: new SessionState(),
  };
}

export function ok(stdout: string, exitCode = 0) {
  return { stdout, stderr: "", exitCode };
}

export function fail(stderr: string, exitCode = 1) {
  return { stdout: "", stderr, exitCode };
}

export function parseEnvelope(result: { content: Array<{ type: string; text: string }> }) {
  return JSON.parse(result.content[0].text);
}
