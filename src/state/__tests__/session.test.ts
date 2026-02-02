import { describe, it, expect } from "vitest";
import { SessionState } from "../session.js";

describe("SessionState", () => {
  it("stores and retrieves archive info by archive filename", () => {
    const state = new SessionState();
    state.storeArchiveInfo("sample.7z", ["payload.exe", "readme.txt"], "7z", "malware");

    const info = state.getArchiveInfo("sample.7z");
    expect(info).toEqual({ format: "7z", password: "malware" });
  });

  it("stores and retrieves archive info by extracted filename", () => {
    const state = new SessionState();
    state.storeArchiveInfo("sample.zip", ["payload.exe"], "zip", "infected");

    const info = state.getArchiveInfo("payload.exe");
    expect(info).toEqual({ format: "zip", password: "infected" });
  });

  it("returns undefined for unknown filenames", () => {
    const state = new SessionState();
    expect(state.getArchiveInfo("unknown.bin")).toBeUndefined();
  });

  it("retrieves archive info by basename of subdirectory path", () => {
    const state = new SessionState();
    state.storeArchiveInfo("sample.zip", ["subdir/payload.exe", "subdir/readme.txt"], "zip", "infected");

    // Lookup by full path
    expect(state.getArchiveInfo("subdir/payload.exe")).toEqual({ format: "zip", password: "infected" });
    // Lookup by basename (how download_file looks it up)
    expect(state.getArchiveInfo("payload.exe")).toEqual({ format: "zip", password: "infected" });
    expect(state.getArchiveInfo("readme.txt")).toEqual({ format: "zip", password: "infected" });
  });

  it("overwrites metadata for duplicate filenames", () => {
    const state = new SessionState();
    state.storeArchiveInfo("a.zip", ["file.exe"], "zip", "pass1");
    state.storeArchiveInfo("b.7z", ["file.exe"], "7z", "pass2");

    const info = state.getArchiveInfo("file.exe");
    expect(info).toEqual({ format: "7z", password: "pass2" });
  });
});
