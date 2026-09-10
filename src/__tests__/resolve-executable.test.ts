/**
 * Tests for the shell-free executable resolver.
 *
 * Why this exists: libuv's uv_spawn resolves a BARE program name by searching
 * the current working directory BEFORE PATH on Windows. From
 * libuv/src/win/process.c, verbatim:
 *
 *   "If there's really only a filename, check the current directory for file,
 *    then search all path directories."
 *
 *   if (NeedCurrentDirectoryForExePathW(L"")) {
 *     // The file is really only a name; look in cwd first, then scan path
 *
 * That branch is taken unless the NoDefaultCurrentDirectoryInExePath environment
 * variable is set, which it is not by default. libuv also appends ".com" before
 * ".exe", so a planted `docker.com` beats a real `docker.exe` on PATH. For a
 * malware-analysis tool whose operator plausibly runs it from a directory where
 * a sample was unpacked, CWD is attacker-influenced.
 *
 * Passing a FULLY QUALIFIED path removes the search entirely — libuv takes the
 * `file_has_dir` branch, and search_path_join_test zeroes the cwd for an
 * absolute path with a drive letter.
 *
 * The resolver is a pure function of (name, PATH string, platform, probe), so
 * Windows semantics are exercised on every runner, not only on Windows.
 */

import { describe, it, expect } from "vitest";
import {
  resolveExecutable,
  isFullyQualified,
  splitPathEnv,
  candidateNames,
} from "../connectors/resolve-executable.js";

describe("isFullyQualified", () => {
  // The security property. `path.win32.isAbsolute()` is NOT a valid test here:
  // it returns true for "\\tools" and "/tools", and libuv resolves those against
  // the CURRENT DRIVE (search_path_join_test sets cwd_len = 2 for them), which
  // keeps the process's cwd in the picture.
  it.each([
    ["C:\\Program Files\\Docker\\docker.exe", true],
    ["c:/tools/docker.exe", true],
    ["\\\\server\\share\\docker.exe", true],
    ["//server/share/docker.exe", true],
    ["\\tools", false], // rooted but drive-less: resolved against the current drive
    ["/tools", false], // same
    ["C:tools", false], // drive-RELATIVE: resolved against that drive's cwd
    ["tools", false],
    [".", false],
    ["..\\tools", false],
    ["", false],
  ])("win32: %s -> %s", (entry, expected) => {
    expect(isFullyQualified(entry, "win32")).toBe(expected);
  });

  it.each([
    ["/usr/local/bin", true],
    ["/opt/homebrew/bin", true],
    ["usr/local/bin", false],
    ["./bin", false],
    ["../bin", false],
    ["", false],
    [".", false],
  ])("posix: %s -> %s", (entry, expected) => {
    expect(isFullyQualified(entry, "linux")).toBe(expected);
  });
});

describe("splitPathEnv", () => {
  it("splits win32 entries on semicolons", () => {
    expect(splitPathEnv("C:\\a;C:\\b", "win32")).toEqual(["C:\\a", "C:\\b"]);
  });

  it("does not split on a semicolon inside a quoted win32 entry", () => {
    // A naive split(';') corrupts this into two broken entries.
    expect(splitPathEnv(`"C:\\weird;dir";C:\\b`, "win32")).toEqual([
      "C:\\weird;dir",
      "C:\\b",
    ]);
  });

  it("strips surrounding quotes from win32 entries", () => {
    expect(splitPathEnv(`"C:\\Program Files\\Docker"`, "win32")).toEqual([
      "C:\\Program Files\\Docker",
    ]);
  });

  it("keeps spaces that are part of a path", () => {
    expect(splitPathEnv("C:\\Program Files\\Docker;C:\\b", "win32")).toEqual([
      "C:\\Program Files\\Docker",
      "C:\\b",
    ]);
  });

  it("splits posix entries on colons", () => {
    expect(splitPathEnv("/usr/bin:/usr/local/bin", "linux")).toEqual([
      "/usr/bin",
      "/usr/local/bin",
    ]);
  });

  it("drops empty entries, which mean 'current directory'", () => {
    // An empty PATH entry is a cwd reference on both platforms.
    expect(splitPathEnv("/usr/bin::/bin", "linux")).toEqual(["/usr/bin", "/bin"]);
    expect(splitPathEnv("C:\\a;;C:\\b", "win32")).toEqual(["C:\\a", "C:\\b"]);
  });

  it("returns nothing for an undefined or empty PATH", () => {
    expect(splitPathEnv(undefined, "linux")).toEqual([]);
    expect(splitPathEnv("", "win32")).toEqual([]);
  });

  // libuv only treats a quote as a quote at the START of an entry
  // ("if (*dir_start == L'\"' || *dir_start == L'\\''"). Treating one anywhere
  // swallows the delimiter after an apostrophe in an ordinary directory name.
  it("treats an apostrophe inside a win32 directory name as a literal character", () => {
    expect(
      splitPathEnv(
        `C:\\Users\\O'Brien\\bin;C:\\Program Files\\Docker\\Docker\\resources\\bin`,
        "win32",
      ),
    ).toEqual([
      `C:\\Users\\O'Brien\\bin`,
      "C:\\Program Files\\Docker\\Docker\\resources\\bin",
    ]);
  });

  it("does not strip apostrophes from the middle of a win32 entry", () => {
    expect(splitPathEnv(`C:\\O'Brien's\\bin`, "win32")).toEqual([`C:\\O'Brien's\\bin`]);
  });

  it("preserves a literal trailing space in a posix entry", () => {
    // On POSIX a trailing space is a legal part of a directory name, so
    // trimming it would silently point at a different directory.
    expect(splitPathEnv("/opt/bin :/usr/bin", "linux")).toEqual([
      "/opt/bin ",
      "/usr/bin",
    ]);
  });

  it("trims cosmetic spacing around win32 entries", () => {
    expect(splitPathEnv("C:\\a; C:\\b", "win32")).toEqual(["C:\\a", "C:\\b"]);
  });
});

describe("candidateNames", () => {
  it("win32 appends .com then .exe for an extensionless name, and never tries the bare name", () => {
    // libuv's path_search_walk_ext only tries the literal name when it already
    // has an extension; CreateProcess cannot run an extensionless file.
    expect(candidateNames("docker", "win32")).toEqual(["docker.com", "docker.exe"]);
  });

  it("win32 tries an explicit extension first, then still appends .com and .exe", () => {
    expect(candidateNames("docker.exe", "win32")).toEqual([
      "docker.exe",
      "docker.exe.com",
      "docker.exe.exe",
    ]);
  });

  it("posix uses the name as given", () => {
    expect(candidateNames("docker", "linux")).toEqual(["docker"]);
  });

  // libuv "adds a dot if the filename didn't end with one", so a name already
  // ending in a dot must not gain a second one.
  it("does not double the dot for a name ending in one", () => {
    expect(candidateNames("docker.", "win32")).toEqual(["docker.com", "docker.exe"]);
  });

  it("reuses a trailing dot after an existing extension", () => {
    expect(candidateNames("docker.cli.", "win32")).toEqual([
      "docker.cli.",
      "docker.cli.com",
      "docker.cli.exe",
    ]);
  });
});

describe("resolveExecutable", () => {
  const probe = (present: string[]) => (p: string) => present.includes(p);

  it("returns the first fully qualified PATH hit on posix", () => {
    const found = resolveExecutable("docker", {
      pathEnv: "/usr/bin:/usr/local/bin",
      platform: "linux",
      isExecutableFile: probe(["/usr/local/bin/docker"]),
    });
    expect(found).toBe("/usr/local/bin/docker");
  });

  it("prefers the earlier PATH directory", () => {
    const found = resolveExecutable("docker", {
      pathEnv: "/usr/bin:/usr/local/bin",
      platform: "linux",
      isExecutableFile: probe(["/usr/bin/docker", "/usr/local/bin/docker"]),
    });
    expect(found).toBe("/usr/bin/docker");
  });

  it("win32 prefers .com over .exe within the same directory, matching libuv", () => {
    const found = resolveExecutable("docker", {
      pathEnv: "C:\\bin",
      platform: "win32",
      isExecutableFile: probe(["C:\\bin\\docker.com", "C:\\bin\\docker.exe"]),
    });
    expect(found).toBe("C:\\bin\\docker.com");
  });

  it("win32 finds docker.exe under a Program Files style path", () => {
    const found = resolveExecutable("docker", {
      pathEnv: "C:\\Windows;C:\\Program Files\\Docker\\Docker\\resources\\bin",
      platform: "win32",
      isExecutableFile: probe([
        "C:\\Program Files\\Docker\\Docker\\resources\\bin\\docker.exe",
      ]),
    });
    expect(found).toBe(
      "C:\\Program Files\\Docker\\Docker\\resources\\bin\\docker.exe",
    );
  });

  // ─── the security property ──────────────────────────────────────────

  it("SECURITY: never resolves via a relative PATH entry, even if a file is there", () => {
    // A relative PATH entry is resolved against the process cwd, which is the
    // attacker-influenced surface this whole change exists to remove.
    const found = resolveExecutable("docker", {
      pathEnv: ".:/usr/bin",
      platform: "linux",
      isExecutableFile: probe(["./docker", "/usr/bin/docker"]),
    });
    expect(found).toBe("/usr/bin/docker");
  });

  it("SECURITY: skips a drive-relative win32 entry that would resolve against the current drive", () => {
    const found = resolveExecutable("docker", {
      pathEnv: "C:tools;C:\\real\\bin",
      platform: "win32",
      isExecutableFile: probe(["C:tools\\docker.exe", "C:\\real\\bin\\docker.exe"]),
    });
    expect(found).toBe("C:\\real\\bin\\docker.exe");
  });

  it("SECURITY: skips a rooted but drive-less win32 entry", () => {
    const found = resolveExecutable("docker", {
      pathEnv: "\\tools;C:\\real\\bin",
      platform: "win32",
      isExecutableFile: probe(["\\tools\\docker.exe", "C:\\real\\bin\\docker.exe"]),
    });
    expect(found).toBe("C:\\real\\bin\\docker.exe");
  });

  it("SECURITY: returns null rather than falling back to the bare name", () => {
    // Returning "docker" here would hand the caller straight back to the
    // libuv cwd-first search this resolver exists to bypass.
    const found = resolveExecutable("docker", {
      pathEnv: "/usr/bin",
      platform: "linux",
      isExecutableFile: probe([]),
    });
    expect(found).toBeNull();
  });

  it("SECURITY: returns null when PATH is unset instead of guessing", () => {
    expect(
      resolveExecutable("docker", {
        pathEnv: undefined,
        platform: "linux",
        isExecutableFile: probe(["./docker", "/usr/bin/docker"]),
      }),
    ).toBeNull();
  });

  it("keeps searching past a directory where the file is absent", () => {
    const found = resolveExecutable("docker", {
      pathEnv: "/empty:/also-empty:/usr/bin",
      platform: "linux",
      isExecutableFile: probe(["/usr/bin/docker"]),
    });
    expect(found).toBe("/usr/bin/docker");
  });

  it("still finds Docker when an earlier PATH entry contains an apostrophe", () => {
    // The regression this guards: a naive quote state machine merges these two
    // entries and the Docker installation becomes unreachable.
    const found = resolveExecutable("docker", {
      pathEnv: `C:\\Users\\O'Brien\\bin;C:\\Program Files\\Docker\\Docker\\resources\\bin`,
      platform: "win32",
      isExecutableFile: probe([
        "C:\\Program Files\\Docker\\Docker\\resources\\bin\\docker.exe",
      ]),
    });
    expect(found).toBe(
      "C:\\Program Files\\Docker\\Docker\\resources\\bin\\docker.exe",
    );
  });

  it("posix: does not treat a trailing backslash as a directory separator", () => {
    // Backslash is a legal filename character on POSIX, not a separator.
    const found = resolveExecutable("docker", {
      pathEnv: "/opt/bin\\",
      platform: "linux",
      isExecutableFile: probe(["/opt/bin\\/docker"]),
    });
    expect(found).toBe("/opt/bin\\/docker");
  });

  it("win32: strips one trailing separator without breaking a drive root", () => {
    expect(
      resolveExecutable("docker", {
        pathEnv: "C:\\",
        platform: "win32",
        isExecutableFile: probe(["C:\\docker.com"]),
      }),
    ).toBe("C:\\docker.com");
  });

  it("resolves through a quoted win32 entry containing a semicolon", () => {
    const found = resolveExecutable("docker", {
      pathEnv: `"C:\\odd;dir"`,
      platform: "win32",
      isExecutableFile: probe(["C:\\odd;dir\\docker.exe"]),
    });
    expect(found).toBe("C:\\odd;dir\\docker.exe");
  });
});
