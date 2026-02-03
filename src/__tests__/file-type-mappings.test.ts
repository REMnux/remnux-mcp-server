import { describe, it, expect } from "vitest";
import {
  matchFileType,
  FILE_TYPE_CATEGORIES,
  CATEGORY_TAG_MAP,
} from "../file-type-mappings.js";

// =========================================================================
// matchFileType
// =========================================================================

describe("matchFileType", () => {
  it("matches PE32 executables", () => {
    const result = matchFileType("sample.exe: PE32 executable (GUI) Intel 80386, for MS Windows");
    expect(result.name).toBe("PE");
  });

  it("matches PE32+ (64-bit) executables", () => {
    const result = matchFileType("sample.exe: PE32+ executable (console) x86-64, for MS Windows");
    expect(result.name).toBe("PE");
  });

  it("matches DLL files (via PE32 pattern)", () => {
    const result = matchFileType("sample.dll: PE32 executable (DLL) Intel 80386, for MS Windows");
    expect(result.name).toBe("PE");
  });

  it("matches MS-DOS executables", () => {
    const result = matchFileType("sample.exe: MS-DOS executable");
    expect(result.name).toBe("PE");
  });

  it("matches PDF files", () => {
    const result = matchFileType("report.pdf: PDF document, version 1.7");
    expect(result.name).toBe("PDF");
  });

  it("matches OLE2 Word documents", () => {
    const result = matchFileType("doc.doc: Composite Document File V2 Document, Microsoft Word");
    expect(result.name).toBe("OLE2");
  });

  it("matches OLE2 Excel files", () => {
    const result = matchFileType("sheet.xls: Composite Document File V2 Document, Microsoft Excel");
    expect(result.name).toBe("OLE2");
  });

  it("matches OOXML Word documents", () => {
    const result = matchFileType("doc.docx: Microsoft Word 2007+");
    expect(result.name).toBe("OOXML");
  });

  it("classifies Microsoft PowerPoint 2007+ as OOXML", () => {
    const result = matchFileType("deck.pptm: Microsoft PowerPoint 2007+");
    expect(result.name).toBe("OOXML");
  });

  it("matches RTF files", () => {
    const result = matchFileType("doc.rtf: Rich Text Format data");
    expect(result.name).toBe("RTF");
  });

  it("matches ELF binaries", () => {
    const result = matchFileType("malware: ELF 64-bit LSB executable, x86-64");
    expect(result.name).toBe("ELF");
  });

  it("matches HTML documents as JavaScript", () => {
    const result = matchFileType("page.html: HTML document, ASCII text");
    expect(result.name).toBe("JavaScript");
  });

  it("matches shell scripts", () => {
    const result = matchFileType("script.sh: Bourne-Again shell script, ASCII text executable");
    expect(result.name).toBe("Script");
  });

  it("matches script text as Script", () => {
    const result = matchFileType("dropper.vbs: ASCII text, with very long lines, script text executable");
    expect(result.name).toBe("Script");
  });

  it("matches Python source scripts as Script", () => {
    const result = matchFileType("dropper.py: Python script, ASCII text executable");
    expect(result.name).toBe("Script");
  });

  it("matches DOS batch files as Script", () => {
    const result = matchFileType("run.bat: DOS batch file, ASCII text");
    expect(result.name).toBe("Script");
  });

  it("matches Python bytecode as Python", () => {
    const result = matchFileType("module.pyc: python 3.8 byte-compiled");
    expect(result.name).toBe("Python");
  });

  it("classifies .js files as JavaScript via extension fallback", () => {
    const result = matchFileType("sample.js: ASCII text", "sample.js");
    expect(result.name).toBe("JavaScript");
  });

  it("classifies .hta files as JavaScript via extension fallback", () => {
    const result = matchFileType("payload.hta: ASCII text, with very long lines", "payload.hta");
    expect(result.name).toBe("JavaScript");
  });

  it("classifies .vbs files as Script via extension fallback", () => {
    const result = matchFileType("dropper.vbs: ASCII text", "dropper.vbs");
    expect(result.name).toBe("Script");
  });

  it("classifies .ps1 files as Script via extension fallback", () => {
    const result = matchFileType("loader.ps1: UTF-8 Unicode text", "loader.ps1");
    expect(result.name).toBe("Script");
  });

  it("classifies .pyc files as Python via extension fallback", () => {
    const result = matchFileType("module.pyc: data", "module.pyc");
    expect(result.name).toBe("Python");
  });

  it("classifies .py files as Script via extension fallback", () => {
    const result = matchFileType("script.py: ASCII text", "script.py");
    expect(result.name).toBe("Script");
  });

  it("classifies plain ASCII text without script extension as Unknown", () => {
    const result = matchFileType("notes.txt: ASCII text", "notes.txt");
    expect(result.name).toBe("Unknown");
  });

  it("classifies plain UTF-8 text without script extension as Unknown", () => {
    const result = matchFileType("log.csv: UTF-8 Unicode text", "log.csv");
    expect(result.name).toBe("Unknown");
  });

  it("matches Java archive files", () => {
    const result = matchFileType("app.jar: Java archive data (JAR)");
    expect(result.name).toBe("JAR");
  });

  it("matches email messages", () => {
    const result = matchFileType("msg.eml: RFC 822 mail text");
    expect(result.name).toBe("Email");
  });

  it("matches Android APK files", () => {
    const result = matchFileType("app.apk: Android application package");
    expect(result.name).toBe("APK");
  });

  it("returns Unknown for unrecognized types", () => {
    const result = matchFileType("mystery.bin: data");
    expect(result.name).toBe("Unknown");
  });

  it("classifies Zip archive as OOXML when filename has .xlsm extension", () => {
    const result = matchFileType("attendees.xlsm: Zip archive data, at least v2.0 to extract", "attendees.xlsm");
    expect(result.name).toBe("OOXML");
  });

  it("classifies Zip archive as OOXML when filename has .docm extension", () => {
    const result = matchFileType("doc.docm: Zip archive data", "doc.docm");
    expect(result.name).toBe("OOXML");
  });

  it("classifies Zip archive as OOXML when filename has .pptm extension", () => {
    const result = matchFileType("deck.pptm: Zip archive data", "deck.pptm");
    expect(result.name).toBe("OOXML");
  });

  it("does not classify Zip archive as OOXML without matching filename", () => {
    const result = matchFileType("sample.zip: Zip archive data", "sample.zip");
    expect(result.name).toBe("Unknown");
  });

  it("matches .NET assemblies as DOTNET (Mono/.Net)", () => {
    const result = matchFileType("sample.exe: PE32 executable, Mono/.Net assembly");
    expect(result.name).toBe("DOTNET");
  });

  it("matches .NET assemblies as DOTNET (.Net assembly)", () => {
    const result = matchFileType("sample.exe: PE32 executable (console) .Net assembly");
    expect(result.name).toBe("DOTNET");
  });

  it("matches PE32 .NET pattern", () => {
    const result = matchFileType("sample.exe: PE32+ executable (console) x86-64 Mono/.Net assembly");
    expect(result.name).toBe("DOTNET");
  });

  it("still matches plain PE32 as PE (not DOTNET)", () => {
    const result = matchFileType("sample.exe: PE32 executable (console) Intel 80386, for MS Windows");
    expect(result.name).toBe("PE");
  });

  it("returns first matching category (PE before others)", () => {
    const result = matchFileType("PE32 executable");
    expect(result.name).toBe("PE");
  });

  it("classifies data files with memory extensions as Memory", () => {
    expect(matchFileType("data", "unknown.img").name).toBe("Memory");
    expect(matchFileType("data", "memdump.raw").name).toBe("Memory");
    expect(matchFileType("data", "capture.mem").name).toBe("Memory");
    expect(matchFileType("data", "snapshot.vmem").name).toBe("Memory");
    expect(matchFileType("data", "crash.dmp").name).toBe("Memory");
    expect(matchFileType("data", "capture.lime").name).toBe("Memory");
  });

  it("does not classify data files without memory or shellcode extensions as Memory", () => {
    expect(matchFileType("data", "sample.dat").name).toBe("Unknown");
    expect(matchFileType("data").name).toBe("Unknown");
  });

  it("classifies data files with shellcode extensions as Shellcode", () => {
    expect(matchFileType("data", "payload.bin").name).toBe("Shellcode");
    expect(matchFileType("data", "code.sc").name).toBe("Shellcode");
    expect(matchFileType("data", "stage.shellcode").name).toBe("Shellcode");
    expect(matchFileType("data", "drop.payload").name).toBe("Shellcode");
  });

  it("does not classify .raw as Shellcode (Memory takes precedence)", () => {
    expect(matchFileType("data", "dump.raw").name).toBe("Memory");
  });

  it("classifies memory images with full path prefix from file command", () => {
    // The `file` command outputs "<path>: <type>" — verify prefix stripping works
    expect(matchFileType("/home/remnux/files/samples/unknown.img: data", "unknown.img").name).toBe("Memory");
    expect(matchFileType("/home/remnux/files/samples/memdump.raw: data", "memdump.raw").name).toBe("Memory");
  });

  it("does not classify non-data files with memory extensions as Memory", () => {
    // If file reports something specific, that takes precedence
    expect(matchFileType("PE32 executable", "sample.img").name).toBe("PE");
  });
});

// =========================================================================
// Category coverage
// =========================================================================

describe("FILE_TYPE_CATEGORIES", () => {
  it("has at least 13 categories", () => {
    expect(FILE_TYPE_CATEGORIES.length).toBeGreaterThanOrEqual(13);
  });

  it("every category has at least one pattern", () => {
    for (const cat of FILE_TYPE_CATEGORIES) {
      expect(cat.patterns.length).toBeGreaterThanOrEqual(1);
    }
  });

  it("every category has a corresponding tag in CATEGORY_TAG_MAP", () => {
    for (const cat of FILE_TYPE_CATEGORIES) {
      expect(CATEGORY_TAG_MAP[cat.name]).toBeDefined();
    }
  });
});
