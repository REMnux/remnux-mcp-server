/**
 * Unit tests for structured error handling.
 */

import { describe, it, expect } from "vitest";
import { REMnuxError } from "../errors/remnux-error.js";
import { toREMnuxError } from "../errors/error-mapper.js";
import { formatError } from "../response.js";

describe("REMnuxError", () => {
  it("constructs with code, category, and remediation", () => {
    const err = new REMnuxError("bad path", "INVALID_PATH", "validation", "Fix the path");
    expect(err.message).toBe("bad path");
    expect(err.code).toBe("INVALID_PATH");
    expect(err.category).toBe("validation");
    expect(err.remediation).toBe("Fix the path");
    expect(err.name).toBe("REMnuxError");
    expect(err).toBeInstanceOf(Error);
  });

  it("works without remediation", () => {
    const err = new REMnuxError("fail", "UNKNOWN_ERROR", "tool_failure");
    expect(err.remediation).toBeUndefined();
  });
});

describe("toREMnuxError", () => {
  it("maps 'is not running' to CONNECTION_FAILED", () => {
    const err = toREMnuxError(new Error("Container is not running"));
    expect(err.code).toBe("CONNECTION_FAILED");
    expect(err.category).toBe("connection");
    expect(err.remediation).toContain("docker start");
  });

  it("maps ECONNREFUSED to CONNECTION_FAILED", () => {
    const err = toREMnuxError(new Error("connect ECONNREFUSED 127.0.0.1:22"));
    expect(err.code).toBe("CONNECTION_FAILED");
    expect(err.category).toBe("connection");
    expect(err.remediation).toContain("SSH");
  });

  it("maps timeout to COMMAND_TIMEOUT", () => {
    const err = toREMnuxError(new Error("Command timeout after 30s"));
    expect(err.code).toBe("COMMAND_TIMEOUT");
    expect(err.category).toBe("timeout");
  });

  it("falls back to UNKNOWN_ERROR", () => {
    const err = toREMnuxError(new Error("something unexpected"));
    expect(err.code).toBe("UNKNOWN_ERROR");
    expect(err.category).toBe("tool_failure");
  });

  it("handles non-Error inputs", () => {
    const err = toREMnuxError("plain string error");
    expect(err.code).toBe("UNKNOWN_ERROR");
    expect(err.message).toBe("plain string error");
  });

  it("passes through existing REMnuxError unchanged", () => {
    const original = new REMnuxError("orig", "INVALID_PATH", "validation", "hint");
    const result = toREMnuxError(original);
    expect(result).toBe(original);
  });
});

describe("formatError with REMnuxError", () => {
  it("includes structured fields in envelope", () => {
    const err = new REMnuxError("blocked", "COMMAND_BLOCKED", "security", "Use allowed tool");
    const result = formatError("run_tool", err, Date.now());
    const envelope = JSON.parse(result.content[0].text);

    expect(envelope.error).toBe("blocked");
    expect(envelope.error_code).toBe("COMMAND_BLOCKED");
    expect(envelope.error_category).toBe("security");
    expect(envelope.remediation).toBe("Use allowed tool");
    expect(envelope.success).toBe(false);
    expect(result.isError).toBe(true);
  });

  it("omits remediation when not provided", () => {
    const err = new REMnuxError("fail", "UNKNOWN_ERROR", "tool_failure");
    const result = formatError("run_tool", err, Date.now());
    const envelope = JSON.parse(result.content[0].text);

    expect(envelope.error_code).toBe("UNKNOWN_ERROR");
    expect(envelope.remediation).toBeUndefined();
  });

  it("plain string errors still work without new fields", () => {
    const result = formatError("get_file_info", "File not found", Date.now());
    const envelope = JSON.parse(result.content[0].text);

    expect(envelope.error).toBe("File not found");
    expect(envelope.error_code).toBeUndefined();
    expect(envelope.error_category).toBeUndefined();
    expect(envelope.remediation).toBeUndefined();
    expect(result.isError).toBe(true);
  });
});
