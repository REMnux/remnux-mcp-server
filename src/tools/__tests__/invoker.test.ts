import { describe, it, expect } from "vitest";
import { buildCommandFromDefinition } from "../invoker.js";
import type { ToolDefinition } from "../registry.js";

const baseTool: ToolDefinition = {
  name: "test-tool",
  description: "Test tool",
  command: "testtool",
  inputStyle: "positional",
  outputFormat: "text",
  timeout: 60,
  tier: "quick",
};

describe("buildCommandFromDefinition", () => {
  it("builds positional command", () => {
    const cmd = buildCommandFromDefinition(baseTool, "/samples/file.exe");
    expect(cmd).toBe("testtool '/samples/file.exe'");
  });

  it("builds flag-based command", () => {
    const tool: ToolDefinition = { ...baseTool, inputStyle: "flag", inputFlag: "-f" };
    const cmd = buildCommandFromDefinition(tool, "/samples/file.exe");
    expect(cmd).toBe("testtool -f '/samples/file.exe'");
  });

  it("builds flag-based command with default --input flag", () => {
    const tool: ToolDefinition = { ...baseTool, inputStyle: "flag" };
    const cmd = buildCommandFromDefinition(tool, "/samples/file.exe");
    expect(cmd).toBe("testtool --input '/samples/file.exe'");
  });

  it("builds stdin command", () => {
    const tool: ToolDefinition = { ...baseTool, inputStyle: "stdin" };
    const cmd = buildCommandFromDefinition(tool, "/samples/file.exe");
    expect(cmd).toBe("testtool < '/samples/file.exe'");
  });

  it("includes fixedArgs before file path", () => {
    const tool: ToolDefinition = { ...baseTool, fixedArgs: ["--stats"] };
    const cmd = buildCommandFromDefinition(tool, "/samples/file.pdf");
    expect(cmd).toBe("testtool --stats '/samples/file.pdf'");
  });

  it("includes suffixArgs after file path", () => {
    const tool: ToolDefinition = {
      ...baseTool,
      inputStyle: "flag",
      inputFlag: "-f",
      suffixArgs: ["windows.info"],
    };
    const cmd = buildCommandFromDefinition(tool, "/samples/image.raw");
    expect(cmd).toBe("testtool -f '/samples/image.raw' windows.info");
  });

  it("builds vol3 command correctly with flag + suffixArgs", () => {
    const tool: ToolDefinition = {
      ...baseTool,
      name: "vol3-pslist",
      command: "vol3",
      inputStyle: "flag",
      inputFlag: "-f",
      suffixArgs: ["windows.pslist"],
    };
    const cmd = buildCommandFromDefinition(tool, "/samples/memdump.raw");
    expect(cmd).toBe("vol3 -f '/samples/memdump.raw' windows.pslist");
  });

  it("escapes single quotes in file path", () => {
    const cmd = buildCommandFromDefinition(baseTool, "/samples/file's.exe");
    expect(cmd).toBe("testtool '/samples/file'\\''s.exe'");
  });

  it("resolves %OUTPUT%/ sentinel in suffixArgs when outputDir is provided", () => {
    const tool: ToolDefinition = {
      ...baseTool,
      suffixArgs: ["%OUTPUT%/autoit-out"],
    };
    const cmd = buildCommandFromDefinition(tool, "/samples/file.exe", "/output");
    expect(cmd).toBe("testtool '/samples/file.exe' /output/autoit-out");
  });

  it("resolves %OUTPUT%/ sentinel in fixedArgs when outputDir is provided", () => {
    const tool: ToolDefinition = {
      ...baseTool,
      fixedArgs: ["-d", "%OUTPUT%/jadx-out", "--no-debug-info"],
    };
    const cmd = buildCommandFromDefinition(tool, "/samples/file.apk", "/output");
    expect(cmd).toBe("testtool -d /output/jadx-out --no-debug-info '/samples/file.apk'");
  });

  it("throws when %OUTPUT%/ sentinel is used without outputDir", () => {
    const tool: ToolDefinition = {
      ...baseTool,
      suffixArgs: ["%OUTPUT%/autoit-out"],
    };
    expect(() => buildCommandFromDefinition(tool, "/samples/file.exe")).toThrow(
      "outputDir is required for tool test-tool but was not provided",
    );
  });

  it("still resolves legacy /tmp/ prefix when outputDir is provided", () => {
    const tool: ToolDefinition = {
      ...baseTool,
      suffixArgs: ["/tmp/legacy-out"],
    };
    const cmd = buildCommandFromDefinition(tool, "/samples/file.exe", "/output");
    expect(cmd).toBe("testtool '/samples/file.exe' /output/legacy-out");
  });

  it("leaves /tmp/ prefix unchanged when outputDir is not provided", () => {
    const tool: ToolDefinition = {
      ...baseTool,
      suffixArgs: ["/tmp/legacy-out"],
    };
    const cmd = buildCommandFromDefinition(tool, "/samples/file.exe");
    expect(cmd).toBe("testtool '/samples/file.exe' /tmp/legacy-out");
  });

});
