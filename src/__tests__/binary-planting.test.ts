/**
 * Filesystem-level tests for the planting scenario.
 *
 * SCOPE, stated precisely, because it is easy to overclaim here. The resolver
 * unit tests use an injected probe and never touch a disk. This file plants a
 * real decoy in the process's current working directory — the exact position
 * libuv searches first for a bare program name — and asserts that the resolver,
 * running against the REAL filesystem probe, does not select it.
 *
 * What this does NOT do: it does not invoke libuv's own executable lookup, so
 * it is not a demonstration that the underlying platform behaviour exists. That
 * behaviour is established from the libuv source (quoted in
 * resolve-executable.ts), not from these tests. What these tests establish is
 * that our resolver makes the right choice when a decoy really is on disk in
 * the cwd, and they fail loudly if someone reintroduces cwd into the search.
 *
 * The last test does cross a real process boundary on POSIX, confirming that
 * the path we resolve is the binary that actually runs.
 */

import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtempSync, mkdirSync, writeFileSync, rmSync, chmodSync } from "node:fs";
import { execFileSync } from "node:child_process";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { resolveExecutable } from "../connectors/resolve-executable.js";

describe("binary planting (native filesystem)", () => {
  let sandbox: string;
  let cwdDir: string;
  let realBinDir: string;
  let originalCwd: string;

  const exeName = process.platform === "win32" ? "docker.exe" : "docker";

  function writeExecutable(dir: string, name: string) {
    const p = join(dir, name);
    writeFileSync(p, process.platform === "win32" ? "MZ" : "#!/bin/sh\nexit 0\n");
    if (process.platform !== "win32") chmodSync(p, 0o755);
    return p;
  }

  beforeEach(() => {
    originalCwd = process.cwd();
    sandbox = mkdtempSync(join(tmpdir(), "planting-"));
    cwdDir = join(sandbox, "unpacked-sample");
    realBinDir = join(sandbox, "real-bin");
    mkdirSync(cwdDir);
    mkdirSync(realBinDir);

    // The analyst's working directory, where a sample was unpacked. The archive
    // dropped a decoy alongside the real files.
    writeExecutable(cwdDir, exeName);
    if (process.platform === "win32") writeExecutable(cwdDir, "docker.com");

    // The genuine installation, on PATH.
    writeExecutable(realBinDir, exeName);

    process.chdir(cwdDir);
  });

  afterEach(() => {
    process.chdir(originalCwd);
    rmSync(sandbox, { recursive: true, force: true });
  });

  it("resolves the PATH installation, not the executable planted in the cwd", () => {
    const resolved = resolveExecutable("docker", {
      pathEnv: realBinDir,
      platform: process.platform,
    });

    expect(resolved).toBe(join(realBinDir, exeName));
    expect(resolved).not.toContain("unpacked-sample");
  });

  it("finds nothing when the only candidate is the planted one in the cwd", () => {
    // The decoy is present and the real probe would accept it if it were ever
    // offered a cwd-relative candidate (the last test in this file proves the
    // probe accepts a fixture of exactly this shape). PATH points at an empty
    // directory, so the only file named `docker` anywhere in play is the decoy,
    // and the resolver still returns nothing.
    const emptyDir = join(sandbox, "empty");
    mkdirSync(emptyDir);

    const resolved = resolveExecutable("docker", {
      pathEnv: emptyDir,
      platform: process.platform,
    });

    expect(resolved).toBeNull();
  });

  it("finds nothing when PATH itself is the cwd expressed relatively", () => {
    const resolved = resolveExecutable("docker", {
      pathEnv: process.platform === "win32" ? ".;.." : ".:..",
      platform: process.platform,
    });

    expect(resolved).toBeNull();
  });

  it("the real default probe accepts a genuine executable", () => {
    // Anti-vacuity for the probe itself: every "null" above would also be
    // produced by a probe that can never return true.
    const resolved = resolveExecutable("docker", {
      pathEnv: realBinDir,
      platform: process.platform,
    });
    expect(resolved).not.toBeNull();
  });

  it.runIf(process.platform !== "win32")(
    "posix: the resolved path is the binary that actually executes",
    () => {
      // Crosses a real process boundary: the two fixtures print different
      // markers, so the output identifies which one ran. Not runnable on
      // Windows, where a two-byte stub is not a valid executable and creating
      // a genuine one is out of scope for a unit test.
      writeFileSync(
        join(cwdDir, "docker"),
        "#!/bin/sh\necho DECOY_FROM_CWD\n",
      );
      chmodSync(join(cwdDir, "docker"), 0o755);
      writeFileSync(
        join(realBinDir, "docker"),
        "#!/bin/sh\necho REAL_FROM_PATH\n",
      );
      chmodSync(join(realBinDir, "docker"), 0o755);

      const resolved = resolveExecutable("docker", {
        pathEnv: realBinDir,
        platform: process.platform,
      });
      expect(resolved).not.toBeNull();

      const output = execFileSync(resolved!, [], { encoding: "utf-8" }).trim();
      expect(output).toBe("REAL_FROM_PATH");
    },
  );

  it.runIf(process.platform !== "win32")(
    "posix: rejects a non-executable file and keeps searching",
    () => {
      const otherDir = join(sandbox, "not-exec");
      mkdirSync(otherDir);
      const p = join(otherDir, "docker");
      writeFileSync(p, "#!/bin/sh\nexit 0\n");
      chmodSync(p, 0o644); // present, but not executable

      const resolved = resolveExecutable("docker", {
        pathEnv: `${otherDir}:${realBinDir}`,
        platform: process.platform,
      });

      expect(resolved).toBe(join(realBinDir, "docker"));
    },
  );
});
