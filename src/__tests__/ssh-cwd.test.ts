/**
 * Unit tests for SSHConnector.buildCwdCommand — the pure cwd-prefixing helper.
 * No SSH connection needed (the constructor only stores config). Verifies that a
 * missing remote working directory is created (mkdir -p) before cd, mirroring the
 * local connector, so a wiped or fresh samples/output dir does not fail tool calls.
 */

import { describe, it, expect } from "vitest";
import { SSHConnector } from "../connectors/ssh.js";

describe("SSHConnector.buildCwdCommand", () => {
  const c = new SSHConnector({ host: "h", user: "remnux", port: 22 });

  it("returns the command unchanged when no cwd is set", () => {
    expect(c.buildCwdCommand("'file' '/x'")).toBe("'file' '/x'");
  });

  it("creates the remote cwd before cd so a missing dir does not fail the call", () => {
    expect(
      c.buildCwdCommand("'file' 'sample.exe'", "/home/remnux/files/samples"),
    ).toBe(
      "mkdir -p '/home/remnux/files/samples' && cd '/home/remnux/files/samples' && 'file' 'sample.exe'",
    );
  });

  it("single-quote escapes the cwd path (no injection)", () => {
    expect(c.buildCwdCommand("ls", "/tmp/it's dir")).toBe(
      "mkdir -p '/tmp/it'\\''s dir' && cd '/tmp/it'\\''s dir' && ls",
    );
  });
});
