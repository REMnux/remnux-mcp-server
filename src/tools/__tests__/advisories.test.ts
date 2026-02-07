import { describe, it, expect } from "vitest";
import { evaluateAdvisories, type AdvisoryContext } from "../advisories.js";

describe("advisories", () => {
  describe("evaluateAdvisories", () => {
    it("returns empty array when no conditions match", () => {
      const context: AdvisoryContext = {
        toolsRun: [
          { name: "diec", exit_code: 0, output: "PE32 executable" },
          { name: "capa", exit_code: 0, output: "Found capabilities" },
        ],
        category: "PE",
      };

      const advisories = evaluateAdvisories(context);
      expect(advisories).toEqual([]);
    });

    it("detects autoit-wrapper condition (ripper failed + diec detected AutoIt)", () => {
      const context: AdvisoryContext = {
        toolsRun: [
          { name: "diec", exit_code: 0, output: "AutoIt v3 compiled" },
          { name: "autoit-ripper", exit_code: 1, output: "Not an AutoIt script" },
        ],
        category: "PE",
      };

      const advisories = evaluateAdvisories(context);
      expect(advisories).toHaveLength(1);
      expect(advisories[0].name).toBe("autoit-wrapper");
      expect(advisories[0].issue).toContain("IExpress/CAB/SFX wrapper");
      expect(advisories[0].remediation).toContain("7z x");
    });

    it("detects AU3! magic in diec output", () => {
      const context: AdvisoryContext = {
        toolsRun: [
          { name: "diec", exit_code: 0, output: "Magic: AU3!" },
          { name: "autoit-ripper", exit_code: 2, output: "Unsupported version" },
        ],
        category: "PE",
      };

      const advisories = evaluateAdvisories(context);
      expect(advisories).toHaveLength(1);
      expect(advisories[0].name).toBe("autoit-wrapper");
    });

    it("does not trigger autoit advisory when ripper succeeds", () => {
      const context: AdvisoryContext = {
        toolsRun: [
          { name: "diec", exit_code: 0, output: "AutoIt v3 compiled" },
          { name: "autoit-ripper", exit_code: 0, output: "Extracted script.au3" },
        ],
        category: "PE",
      };

      const advisories = evaluateAdvisories(context);
      expect(advisories).toEqual([]);
    });

    it("does not trigger autoit advisory when diec doesn't detect AutoIt", () => {
      const context: AdvisoryContext = {
        toolsRun: [
          { name: "diec", exit_code: 0, output: "UPX packed" },
          { name: "autoit-ripper", exit_code: 1, output: "Not an AutoIt script" },
        ],
        category: "PE",
      };

      const advisories = evaluateAdvisories(context);
      expect(advisories).toEqual([]);
    });

    it("detects capa-packed condition (exit code 14)", () => {
      const context: AdvisoryContext = {
        toolsRun: [{ name: "capa", exit_code: 14, output: "Packed file" }],
        category: "PE",
      };

      const advisories = evaluateAdvisories(context);
      expect(advisories).toHaveLength(1);
      expect(advisories[0].name).toBe("capa-packed");
      expect(advisories[0].issue).toContain("packed");
      expect(advisories[0].remediation).toContain("upx -d");
    });

    it("returns advisories sorted by priority (highest first)", () => {
      const context: AdvisoryContext = {
        toolsRun: [
          { name: "diec", exit_code: 0, output: "AutoIt v3" },
          { name: "autoit-ripper", exit_code: 1, output: "Failed" },
          { name: "capa", exit_code: 14, output: "Packed" },
          { name: "yara-forge", exit_code: 0, output: "MALWARE_Win_Qulab" },
        ],
        category: "PE",
      };

      const advisories = evaluateAdvisories(context);
      expect(advisories).toHaveLength(3);
      // autoit-wrapper=10, capa-packed=9, yara-family-attribution=7
      expect(advisories[0].name).toBe("autoit-wrapper");
      expect(advisories[1].name).toBe("capa-packed");
      expect(advisories[2].name).toBe("yara-family-attribution");
    });

    it("detects yara-family-attribution when yara-forge has match lines", () => {
      const context: AdvisoryContext = {
        toolsRun: [
          { name: "yara-forge", exit_code: 0, output: "MALWARE_Win_Qulab sample.exe\nMALWARE_Win_AgentTesla sample.exe" },
        ],
        category: "PE",
      };

      const advisories = evaluateAdvisories(context);
      expect(advisories).toHaveLength(1);
      expect(advisories[0].name).toBe("yara-family-attribution");
      expect(advisories[0].issue).toContain("resemblance");
      expect(advisories[0].remediation).toContain("Cross-reference");
    });

    it("does not trigger yara-family-attribution when output is only warnings", () => {
      const context: AdvisoryContext = {
        toolsRun: [
          { name: "yara-forge", exit_code: 0, output: "warning: slow rule\nwarning: skipped rule" },
        ],
        category: "PE",
      };

      const advisories = evaluateAdvisories(context);
      expect(advisories).toEqual([]);
    });

    it("does not trigger yara-family-attribution when yara-forge has no output", () => {
      const context: AdvisoryContext = {
        toolsRun: [
          { name: "yara-forge", exit_code: 0, output: "" },
        ],
        category: "PE",
      };

      const advisories = evaluateAdvisories(context);
      expect(advisories).toEqual([]);
    });

    it("does not trigger yara-family-attribution when yara-forge was not run", () => {
      const context: AdvisoryContext = {
        toolsRun: [
          { name: "capa", exit_code: 0, output: "Found capabilities" },
        ],
        category: "PE",
      };

      const advisories = evaluateAdvisories(context);
      expect(advisories).toEqual([]);
    });
  });
});
