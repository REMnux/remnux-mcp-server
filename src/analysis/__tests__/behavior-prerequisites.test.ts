import { describe, it, expect } from "vitest";
import {
  BEHAVIOR_PREREQUISITES,
  classifyPrerequisite,
  hasDynamicResolution,
} from "../behavior-prerequisites.js";

const CLIPBOARD = BEHAVIOR_PREREQUISITES.clipboard_hijacking;
const notObscured = { obscured: false, importsParsed: true };

function set(...names: string[]) {
  return new Set(names.map((n) => n.toLowerCase()));
}

describe("hasDynamicResolution", () => {
  it("requires BOTH GetProcAddress and a library loader", () => {
    expect(hasDynamicResolution(set("GetProcAddress", "LoadLibraryExW"))).toBe(true);
    expect(hasDynamicResolution(set("GetProcAddress"))).toBe(false);
    expect(hasDynamicResolution(set("LoadLibraryW"))).toBe(false);
  });
});

describe("classifyPrerequisite", () => {
  it("capable_statically when enough prerequisite APIs are imported", () => {
    const r = classifyPrerequisite("clipboard_hijacking", CLIPBOARD, set("OpenClipboard", "SetClipboardData"), notObscured);
    expect(r.static_capability).toBe("capable_statically");
    expect(r.apis_present).toEqual(["OpenClipboard", "SetClipboardData"]);
  });

  it("incapable_statically when APIs absent and no dynamic-resolution primitives", () => {
    const r = classifyPrerequisite("clipboard_hijacking", CLIPBOARD, set("CreateFileW", "ReadFile"), notObscured);
    expect(r.static_capability).toBe("incapable_statically");
    expect(r.apis_present).toEqual([]);
  });

  it("possibly_via_dynamic_resolution when APIs absent but GetProcAddress + loader present", () => {
    const r = classifyPrerequisite(
      "clipboard_hijacking",
      CLIPBOARD,
      set("GetProcAddress", "LoadLibraryExW", "CreateFileW"),
      notObscured,
    );
    expect(r.static_capability).toBe("possibly_via_dynamic_resolution");
    expect(r.dynamic_resolution_present).toBe(true);
  });

  it("analysis_incomplete on a packed/obscured binary instead of a false 'incapable'", () => {
    const r = classifyPrerequisite("clipboard_hijacking", CLIPBOARD, set("GetProcAddress", "LoadLibraryExW"), {
      obscured: true,
      importsParsed: true,
    });
    expect(r.static_capability).toBe("analysis_incomplete");
    expect(r.recommended_followup).toMatch(/unpack/i);
  });

  it("analysis_incomplete when the import table could not be read", () => {
    const r = classifyPrerequisite("clipboard_hijacking", CLIPBOARD, set(), { obscured: false, importsParsed: false });
    expect(r.static_capability).toBe("analysis_incomplete");
  });

  it("analysis_incomplete with a .NET rationale for managed binaries (not a false negative)", () => {
    const r = classifyPrerequisite("clipboard_hijacking", CLIPBOARD, set("_CorExeMain"), {
      obscured: false,
      importsParsed: false,
      managed: true,
    });
    expect(r.static_capability).toBe("analysis_incomplete");
    expect(r.rationale).toMatch(/\.NET|managed/i);
    expect(r.recommended_followup).toMatch(/ilspycmd|dnSpy|\.NET/i);
  });

  it("capable_statically wins even on a packed binary when the APIs ARE imported", () => {
    const r = classifyPrerequisite("clipboard_hijacking", CLIPBOARD, set("OpenClipboard", "GetClipboardData"), {
      obscured: true,
      importsParsed: true,
    });
    expect(r.static_capability).toBe("capable_statically");
  });

  it("never names the assessment a 'verdict' and always self-qualifies as static", () => {
    const r = classifyPrerequisite("clipboard_hijacking", CLIPBOARD, set("OpenClipboard", "GetClipboardData"), notObscured);
    expect(r).toHaveProperty("static_capability");
    expect(r).not.toHaveProperty("verdict");
    expect(r.static_capability.endsWith("_statically") || r.static_capability === "analysis_incomplete").toBe(true);
    expect(r.rationale).toMatch(/not evidence the behavior executes|does not confirm|cannot/i);
  });
});
