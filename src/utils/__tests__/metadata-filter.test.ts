import { describe, it, expect } from "vitest";
import { filterMetadataLines } from "../metadata-filter.js";

describe("filterMetadataLines", () => {
  describe("should filter author lines", () => {
    it("filters author with email", () => {
      const input = "author: mehunhoff@google.com\nmalicious.exe";
      expect(filterMetadataLines(input)).toBe("malicious.exe");
    });

    it("filters author with name", () => {
      const input = "author: John Doe\nC2: evil.com";
      expect(filterMetadataLines(input)).toBe("C2: evil.com");
    });

    it("filters author with equals separator", () => {
      const input = "author = someone@example.com\nevil.com";
      expect(filterMetadataLines(input)).toBe("evil.com");
    });
  });

  describe("should filter reference lines", () => {
    it("filters reference with URL", () => {
      const input = "reference: https://mandiant.com/resources/...\nC2: evil.com";
      expect(filterMetadataLines(input)).toBe("C2: evil.com");
    });

    it("filters reference with domain", () => {
      const input = "reference: mandiant.com\nDropped: malware.exe";
      expect(filterMetadataLines(input)).toBe("Dropped: malware.exe");
    });
  });

  describe("should filter other metadata fields", () => {
    it("filters namespace", () => {
      const input = "namespace: malware/loader\nevil.com";
      expect(filterMetadataLines(input)).toBe("evil.com");
    });

    it("filters description", () => {
      const input = "description: This rule detects...\nevil.com";
      expect(filterMetadataLines(input)).toBe("evil.com");
    });

    it("filters version", () => {
      const input = "version: 1.0.0\nevil.com";
      expect(filterMetadataLines(input)).toBe("evil.com");
    });

    it("filters maintainer", () => {
      const input = "maintainer: security-team@company.com\nevil.com";
      expect(filterMetadataLines(input)).toBe("evil.com");
    });

    it("filters contributor", () => {
      const input = "contributor: researcher@example.org\nevil.com";
      expect(filterMetadataLines(input)).toBe("evil.com");
    });

    it("filters source", () => {
      const input = "source: https://github.com/example/rules\nevil.com";
      expect(filterMetadataLines(input)).toBe("evil.com");
    });
  });

  describe("should filter JSON-format metadata (capa output)", () => {
    it("filters JSON author field", () => {
      const input = '  "author": "mehunhoff@google.com",\nevil.com';
      expect(filterMetadataLines(input)).toBe("evil.com");
    });

    it("filters JSON reference field", () => {
      const input = '    "reference": "https://mandiant.com/resources/report",\nevil.com';
      expect(filterMetadataLines(input)).toBe("evil.com");
    });

    it("filters JSON description field", () => {
      const input = '"description": "Detects malware family X",\nevil.com';
      expect(filterMetadataLines(input)).toBe("evil.com");
    });

    it("filters JSON source field", () => {
      const input = '"source": "https://github.com/repo/rules",\nevil.com';
      expect(filterMetadataLines(input)).toBe("evil.com");
    });
  });

  describe("should filter comment-prefixed metadata", () => {
    it("filters // comment author", () => {
      const input = "// author: test@example.com\nevil.com";
      expect(filterMetadataLines(input)).toBe("evil.com");
    });

    it("filters # comment reference", () => {
      const input = "# reference: mandiant.com\nevil.com";
      expect(filterMetadataLines(input)).toBe("evil.com");
    });

    it("filters ; comment namespace", () => {
      const input = "; namespace: malware\nevil.com";
      expect(filterMetadataLines(input)).toBe("evil.com");
    });

    it("filters -- comment author", () => {
      const input = "-- author: researcher@example.com\nevil.com";
      expect(filterMetadataLines(input)).toBe("evil.com");
    });

    it("filters comment-prefixed description", () => {
      const input = "# description: This rule detects...\nevil.com";
      expect(filterMetadataLines(input)).toBe("evil.com");
    });

    it("filters comment-prefixed source", () => {
      const input = "// source: https://github.com/rules\nevil.com";
      expect(filterMetadataLines(input)).toBe("evil.com");
    });
  });

  describe("should preserve legitimate IOC lines", () => {
    it("preserves C2 lines", () => {
      const input = "C2 server: evil.com\nDropped file: malware.exe";
      expect(filterMetadataLines(input)).toBe(input);
    });

    it("preserves IP addresses", () => {
      const input = "192.168.1.1\n10.0.0.1\n8.8.8.8";
      expect(filterMetadataLines(input)).toBe(input);
    });

    it("preserves URLs without metadata prefix", () => {
      const input = "https://evil.com/payload.exe\nhttp://c2.example.com";
      expect(filterMetadataLines(input)).toBe(input);
    });

    it("preserves hashes", () => {
      const input = "SHA256: abc123def456\nMD5: 123456";
      expect(filterMetadataLines(input)).toBe(input);
    });

    it("preserves registry keys", () => {
      const input = "HKLM\\Software\\Malware\\Run\nHKCU\\CurrentVersion";
      expect(filterMetadataLines(input)).toBe(input);
    });

    it("preserves file paths", () => {
      const input = "C:\\Windows\\System32\\malware.dll\n/tmp/payload.sh";
      expect(filterMetadataLines(input)).toBe(input);
    });
  });

  describe("should handle edge cases", () => {
    it("handles empty input", () => {
      expect(filterMetadataLines("")).toBe("");
    });

    it("handles input with only metadata", () => {
      const input = "author: test@example.com\nreference: mandiant.com";
      expect(filterMetadataLines(input)).toBe("");
    });

    it("handles mixed metadata and IOCs", () => {
      const input = `author: researcher@google.com
reference: https://mandiant.com/resources/report
C2: evil.com
namespace: malware/loader
192.168.1.100
source: https://github.com/repo
https://actual-ioc.com/payload`;
      const expected = `C2: evil.com
192.168.1.100
https://actual-ioc.com/payload`;
      expect(filterMetadataLines(input)).toBe(expected);
    });

    it("preserves lines with author/reference in middle", () => {
      // These shouldn't match because the keyword isn't at line start
      const input = "Found author string in binary\nCheck reference at line 42";
      expect(filterMetadataLines(input)).toBe(input);
    });

    it("handles whitespace at line start", () => {
      const input = "  author: test@example.com\nevil.com";
      // Trimmed before matching, so this should still filter
      expect(filterMetadataLines(input)).toBe("evil.com");
    });
  });
});
