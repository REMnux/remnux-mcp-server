import { describe, it, expect } from "vitest";
import { parseReadelfOutput } from "../readelf.js";

describe("parseReadelfOutput", () => {
  it("parses ELF header fields", () => {
    const output = [
      "ELF Header:",
      "  Class:                             ELF64",
      "  Type:                              EXEC (Executable file)",
      "  Machine:                           Advanced Micro Devices X86-64",
      "  Entry point address:               0x401000",
    ].join("\n");

    const result = parseReadelfOutput(output);
    expect(result.parsed).toBe(true);
    expect(result.metadata.elf_type).toBe("EXEC (Executable file)");
    expect(result.metadata.machine).toBe("Advanced Micro Devices X86-64");
    expect(result.metadata.entry_point).toBe("0x401000");
  });

  it("flags 0x0 entry point", () => {
    const output = [
      "  Type:                              DYN (Shared object file)",
      "  Entry point address:               0x0",
    ].join("\n");

    const result = parseReadelfOutput(output);
    expect(result.parsed).toBe(true);
    expect(result.findings).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ category: "binary-info", severity: "info" }),
      ])
    );
  });

  it("returns unparsed for empty output", () => {
    const result = parseReadelfOutput("");
    expect(result.parsed).toBe(false);
  });
});
