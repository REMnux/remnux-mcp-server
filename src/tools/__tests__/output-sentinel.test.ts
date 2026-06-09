import { describe, it, expect } from "vitest";
import {
  buildCommandFromDefinition,
  buildInvocationTemplate,
  resolveOutputPath,
} from "../invoker.js";
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

describe("resolveOutputPath", () => {
  it("resolves the %OUTPUT% sentinel to the output directory", () => {
    expect(resolveOutputPath("%OUTPUT%/box-js-out", "/output", "box-js")).toBe(
      "/output/box-js-out",
    );
  });

  it("throws (naming the tool) when the sentinel is used without an outputDir", () => {
    expect(() => resolveOutputPath("%OUTPUT%/x", undefined, "box-js")).toThrow(
      "outputDir is required for tool box-js but was not provided",
    );
  });

  it("resolves the legacy /tmp/ prefix when outputDir is set", () => {
    expect(resolveOutputPath("/tmp/decrypted.pdf", "/output", "qpdf")).toBe(
      "/output/decrypted.pdf",
    );
  });

  it("leaves /tmp/ unchanged when no outputDir (legacy passthrough)", () => {
    expect(resolveOutputPath("/tmp/x", undefined, "qpdf")).toBe("/tmp/x");
  });

  it("leaves non-output arguments untouched", () => {
    expect(resolveOutputPath("--decrypt", "/output", "qpdf")).toBe("--decrypt");
  });
});

describe("buildCommandFromDefinition with %OUTPUT%", () => {
  it("resolves %OUTPUT% in fixedArgs", () => {
    const tool: ToolDefinition = {
      ...baseTool,
      fixedArgs: ["--output-dir", "%OUTPUT%/box-js-out"],
    };
    expect(buildCommandFromDefinition(tool, "/samples/a.js", "/output")).toBe(
      "testtool --output-dir /output/box-js-out '/samples/a.js'",
    );
  });

  it("resolves %OUTPUT% in suffixArgs", () => {
    const tool: ToolDefinition = {
      ...baseTool,
      suffixArgs: ["%OUTPUT%/decrypted.pdf"],
    };
    expect(buildCommandFromDefinition(tool, "/samples/a.pdf", "/output")).toBe(
      "testtool '/samples/a.pdf' /output/decrypted.pdf",
    );
  });

  it("throws when %OUTPUT% is present but no outputDir is provided", () => {
    const tool: ToolDefinition = { ...baseTool, suffixArgs: ["%OUTPUT%/x"] };
    expect(() => buildCommandFromDefinition(tool, "/samples/a")).toThrow(
      "outputDir is required",
    );
  });
});

describe("buildInvocationTemplate", () => {
  it("uses the real command (not the registry name) for .py tools", () => {
    const tool: ToolDefinition = { ...baseTool, name: "emldump", command: "emldump.py" };
    expect(buildInvocationTemplate(tool)).toBe("emldump.py <file>");
  });

  it("renders the full canonical invocation for a pseudo-tool alias", () => {
    const tool: ToolDefinition = {
      ...baseTool,
      name: "vol3-pslist",
      command: "vol3",
      inputStyle: "flag",
      inputFlag: "-f",
      suffixArgs: ["windows.pslist"],
    };
    expect(buildInvocationTemplate(tool)).toBe("vol3 -f <file> windows.pslist");
  });

  it("renders fixedArgs for verbose aliases (capa-vv)", () => {
    const tool: ToolDefinition = {
      ...baseTool,
      name: "capa-vv",
      command: "capa",
      fixedArgs: ["-vv"],
    };
    expect(buildInvocationTemplate(tool)).toBe("capa -vv <file>");
  });

  it("preserves the %OUTPUT% sentinel in the template (resolved later, at run time)", () => {
    const tool: ToolDefinition = {
      ...baseTool,
      name: "box-js",
      command: "box-js",
      fixedArgs: ["--output-dir", "%OUTPUT%/box-js-out"],
    };
    expect(buildInvocationTemplate(tool)).toBe(
      "box-js --output-dir %OUTPUT%/box-js-out <file>",
    );
  });
});
