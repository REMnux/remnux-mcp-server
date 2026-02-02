/**
 * Unit tests for the response envelope helpers.
 */

import { describe, it, expect } from "vitest";
import { formatResponse, formatError } from "../response.js";

describe("formatResponse", () => {
  it("returns success envelope with data and timing", () => {
    const startTime = Date.now() - 42;
    const result = formatResponse("run_tool", { command: "ls", stdout: "file.txt" }, startTime);

    const envelope = JSON.parse(result.content[0].text);
    expect(envelope.success).toBe(true);
    expect(envelope.tool).toBe("run_tool");
    expect(envelope.data.command).toBe("ls");
    expect(envelope.data.stdout).toBe("file.txt");
    expect(envelope.error).toBeUndefined();
    expect(envelope.metadata.elapsed_ms).toBeGreaterThanOrEqual(0);
    expect(result.isError).toBeUndefined();
  });

  it("does not set isError on success responses", () => {
    const result = formatResponse("list_files", { entries: "" }, Date.now());
    expect(result.isError).toBeUndefined();
  });
});

describe("formatError", () => {
  it("returns error envelope with isError true", () => {
    const startTime = Date.now() - 10;
    const result = formatError("get_file_info", "File not found", startTime);

    const envelope = JSON.parse(result.content[0].text);
    expect(envelope.success).toBe(false);
    expect(envelope.tool).toBe("get_file_info");
    expect(envelope.error).toBe("File not found");
    expect(envelope.data).toEqual({});
    expect(envelope.metadata.elapsed_ms).toBeGreaterThanOrEqual(0);
    expect(result.isError).toBe(true);
  });

  it("always sets isError to true", () => {
    const result = formatError("download_file", "too large", Date.now());
    expect(result.isError).toBe(true);
  });
});
