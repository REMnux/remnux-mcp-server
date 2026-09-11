/**
 * Container and packer labels in the triage summary come from diec's detections,
 * not from any tool's text. Unpackers name their technology when they fail, and
 * tools echo the sample's name, so text matching labeled files that were neither.
 */

import { describe, it, expect, vi } from "vitest";
import { handleAnalyzeFile } from "../analyze-file.js";
import { createMockDeps, ok, parseEnvelope } from "./helpers.js";

type Detection = { type: string; name: string };

/** diec --json output carrying the given detections. */
const diecJson = (values: Detection[]) =>
  JSON.stringify({
    detects: [{ filetype: "PE32", values: values.map((v) => ({ ...v, string: `${v.type}: ${v.name}`, info: "" })) }],
  });

/**
 * Every tool other than diec prints the failure text of the unpackers in the PE
 * chain (measured wording) and echoes the sample's name, as real tools do.
 */
const otherToolText = (file: string) =>
  [
    "ERROR:autoit_ripper.autoit_unpack:Couldn't find the EA05 location chunk",
    `upx: ${file}: NotPackedException: not packed by UPX`,
    `processed /samples/${file}`,
  ].join("\n");

async function triage(file: string, detections: Detection[]): Promise<string> {
  const deps = createMockDeps();
  vi.mocked(deps.connector.execute).mockResolvedValue(
    ok(`/samples/${file}: PE32 executable (GUI) Intel 80386, for MS Windows`),
  );
  vi.mocked(deps.connector.executeShell).mockImplementation(async (cmd: string) =>
    cmd.startsWith("diec") ? ok(diecJson(detections)) : ok(otherToolText(file)),
  );
  const env = parseEnvelope(await handleAnalyzeFile(deps, { file, depth: "standard" }));
  return env.data.triage_summary;
}

describe("analyze_file: container and packer labels", () => {
  // Types as DIE's signature files declare them; the patterns ignore case.
  it.each([
    [{ type: "Packer", name: "UPX" }, "UPX packed"],
    [{ type: "Installer", name: "Nullsoft Scriptable Install System" }, "NSIS installer"],
    [{ type: "Installer", name: "Inno Setup Module" }, "Inno Setup"],
    [{ type: "Packer", name: "PyInstaller" }, "PyInstaller"],
    [{ type: "Format", name: "AutoIt" }, "AutoIt compiled"],
    [{ type: "Protector", name: "VMProtect" }, "protected"],
    [{ type: "Sfx", name: "Microsoft Cabinet" }, "Microsoft Cabinet SFX"],
  ])("labels diec's %o as %s", async (detection, label) => {
    expect(await triage("sample.exe", [detection])).toContain(label);
  });

  it("ignores unpacker failure text and the sample's name when diec detects no packer", async () => {
    const summary = await triage("UPX.exe", [{ type: "Compiler", name: "Microsoft Visual C/C++" }]);
    expect(summary).not.toContain("UPX packed");
    expect(summary).not.toContain("AutoIt compiled");
  });
});
