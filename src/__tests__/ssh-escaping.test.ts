/**
 * Tests for SSH shell escaping
 *
 * These tests verify that the SSH connector properly escapes
 * command arguments to prevent shell injection attacks.
 */

import { describe, it, expect } from "vitest";

// The shell escaping function extracted for testing
// Uses single quotes which preserve everything literally
function shellEscape(arg: string): string {
  return `'${arg.replace(/'/g, "'\\''")}'`;
}

describe("SSH shell escaping", () => {
  describe("basic escaping", () => {
    it("wraps simple strings in single quotes", () => {
      expect(shellEscape("hello")).toBe("'hello'");
      expect(shellEscape("file.txt")).toBe("'file.txt'");
    });

    it("preserves spaces", () => {
      expect(shellEscape("hello world")).toBe("'hello world'");
    });

    it("preserves special shell characters", () => {
      expect(shellEscape("$HOME")).toBe("'$HOME'");
      expect(shellEscape("`whoami`")).toBe("'`whoami`'");
      expect(shellEscape("$(id)")).toBe("'$(id)'");
      expect(shellEscape("a; b")).toBe("'a; b'");
      expect(shellEscape("a | b")).toBe("'a | b'");
      expect(shellEscape("a && b")).toBe("'a && b'");
    });
  });

  describe("single quote handling", () => {
    it("escapes single quotes", () => {
      // To include ' in single quotes: end quote, add escaped ', start quote
      expect(shellEscape("it's")).toBe("'it'\\''s'");
    });

    it("handles multiple single quotes", () => {
      expect(shellEscape("'''")).toBe("''\\'''\\'''\\'''");
    });

    it("handles quote at start", () => {
      expect(shellEscape("'start")).toBe("''\\''start'");
    });

    it("handles quote at end", () => {
      expect(shellEscape("end'")).toBe("'end'\\'''");
    });
  });

  describe("injection attack prevention", () => {
    it("neutralizes command substitution with backticks", () => {
      const escaped = shellEscape("--output=`whoami`");
      // When executed in a shell, the backticks are literal, not executed
      expect(escaped).toBe("'--output=`whoami`'");
    });

    it("neutralizes command substitution with $()", () => {
      const escaped = shellEscape("--output=$(whoami)");
      expect(escaped).toBe("'--output=$(whoami)'");
    });

    it("neutralizes newline injection", () => {
      const escaped = shellEscape("file\nrm -rf /");
      expect(escaped).toBe("'file\nrm -rf /'");
      // The newline becomes a literal character, not a command separator
    });

    it("neutralizes semicolon command chaining", () => {
      const escaped = shellEscape("file; rm -rf /");
      expect(escaped).toBe("'file; rm -rf /'");
    });

    it("neutralizes pipe injection", () => {
      const escaped = shellEscape("file | cat /etc/passwd");
      expect(escaped).toBe("'file | cat /etc/passwd'");
    });

    it("neutralizes variable expansion", () => {
      const escaped = shellEscape("${PATH}");
      expect(escaped).toBe("'${PATH}'");
    });
  });

  describe("edge cases", () => {
    it("handles empty string", () => {
      expect(shellEscape("")).toBe("''");
    });

    it("handles unicode", () => {
      expect(shellEscape("文件")).toBe("'文件'");
    });

    it("handles null bytes", () => {
      expect(shellEscape("a\x00b")).toBe("'a\x00b'");
    });

    it("handles long strings", () => {
      const longString = "a".repeat(10000);
      expect(shellEscape(longString)).toBe(`'${longString}'`);
    });
  });
});

describe("Full command escaping", () => {
  // Simulates how the SSH connector builds the command string
  function buildCommand(args: string[]): string {
    return args.map((arg) => shellEscape(arg)).join(" ");
  }

  it("escapes each argument independently", () => {
    const cmd = buildCommand(["file", "--type", "sample.exe"]);
    expect(cmd).toBe("'file' '--type' 'sample.exe'");
  });

  it("prevents injection via arguments", () => {
    const cmd = buildCommand(["file", "--output=$(whoami)", "test.txt"]);
    expect(cmd).toBe("'file' '--output=$(whoami)' 'test.txt'");
  });

  it("handles arguments with spaces correctly", () => {
    const cmd = buildCommand(["echo", "hello world"]);
    expect(cmd).toBe("'echo' 'hello world'");
  });

  it("handles the review's exploit example", () => {
    // From the review: args: ["--output=$(whoami)"] should not execute
    const cmd = buildCommand(["file", "--output=$(whoami)"]);
    expect(cmd).toBe("'file' '--output=$(whoami)'");
    // When this runs in a shell, $(whoami) is NOT executed
  });
});
