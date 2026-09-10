/**
 * Regression tests for GHSA-qp43-2vqh-w88w.
 *
 * `docker cp` used to be composed as a shell command string and run through
 * `execSync`, protected only by POSIX single-quote escaping. That escaping is
 * inert under cmd.exe (single quotes are literal there), so a filename carrying
 * `&` or `>` executed on the analyst's Windows workstation — outside the
 * container isolation the threat model relies on.
 *
 * The fix is structural: build an argument vector and execute it with no shell.
 * These tests pin that invariant at two levels — the pure argv builders, and the
 * three transfer methods that must actually use them — plus a source-level guard
 * so the shell-string form cannot come back.
 *
 * Note on platform: the injection only fires under cmd.exe, and these tests run
 * on the host's platform. They do not "prove Windows is fixed" by executing
 * there. They prove the platform-independent invariant that removes the bug on
 * every platform: no shell is involved, and no metacharacter is ever escaped,
 * quoted, or split — each path crosses the boundary as one argv element.
 */

import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { readFileSync, existsSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const execFileSyncMock = vi.fn();
const execSyncMock = vi.fn();

// Flipped by the stopped-container test; reset in beforeEach.
let containerRunning = true;

vi.mock("child_process", () => ({
  execFileSync: (...args: unknown[]) => execFileSyncMock(...args),
  execSync: (...args: unknown[]) => execSyncMock(...args),
}));

vi.mock("dockerode", () => ({
  default: class {
    getContainer() {
      return { inspect: async () => ({ State: { Running: containerRunning } }) };
    }
  },
}));

// The connector resolves `docker` to a fully qualified path rather than letting
// libuv search (which would consult the cwd first on Windows — see
// resolve-executable.ts). Stubbed here so these tests do not require Docker to
// be installed on the runner; the resolver has its own suites.
// Must be fully qualified on the platform the test is running on, or the stub
// would assert a shape the real resolver could never produce here.
const RESOLVED_DOCKER =
  process.platform === "win32"
    ? "C:\\Program Files\\Docker\\Docker\\resources\\bin\\docker.exe"
    : "/usr/local/bin/docker";
const resolveExecutableMock =
  vi.fn<(name: string, options: unknown) => string | null>(() => RESOLVED_DOCKER);
vi.mock("../connectors/resolve-executable.js", () => ({
  resolveExecutable: (name: string, options: unknown) =>
    resolveExecutableMock(name, options),
}));

const { DockerConnector } = await import("../connectors/docker.js");

// A basename exercising every character that means something to cmd.exe, plus a
// space, a POSIX metacharacter set, and the single quote the old escaper keyed on.
// Used only where the value stays a string — no filesystem call ever sees it.
const NASTY = `rep ort.txt&echo PWNED>marker.txt|dir%USERNAME%^(x)!DELAYED!;$(id)\`id\`'"`;

// The subset that is legal in a real Windows filename (`< > : " / \ | ? *` are not),
// for the tests that actually create a file — otherwise they cannot run on Windows,
// which is the only platform the vulnerability fires on. This is also exactly what a
// real Windows attack is limited to, so it is the sharper adversarial case, not a
// watered-down one.
const NASTY_FS_SAFE = `rep ort.bin&echo PWNED&dir %USERNAME%^(x)!DELAYED!;$(id)\`id\`'`;

beforeEach(() => {
  execFileSyncMock.mockReset();
  execSyncMock.mockReset();
  resolveExecutableMock.mockReset();
  resolveExecutableMock.mockReturnValue(RESOLVED_DOCKER);
  containerRunning = true;
});

afterEach(() => {
  vi.restoreAllMocks();
});

describe("DockerConnector argv builders (pure)", () => {
  it("buildCopyFromContainerArgv carries the remote path as one unmodified element", () => {
    const c = new DockerConnector("remnux");
    const remote = `/home/remnux/files/output/${NASTY}`;
    const host = `/Users/analyst/dl/${NASTY}`;

    const argv = c.buildCopyFromContainerArgv(remote, host);

    expect(argv).toEqual(["cp", `remnux:${remote}`, host]);
    expect(argv).toHaveLength(3);
  });

  it("buildCopyToContainerArgv carries the host path as one unmodified element", () => {
    const c = new DockerConnector("remnux");
    const host = `/Users/analyst/staging/${NASTY}`;
    const remote = `/home/remnux/files/samples/${NASTY}`;

    const argv = c.buildCopyToContainerArgv(host, remote);

    expect(argv).toEqual(["cp", host, `remnux:${remote}`]);
    expect(argv).toHaveLength(3);
  });

  it("adds no shell escaping of any kind", () => {
    const c = new DockerConnector("remnux");
    const argv = c.buildCopyFromContainerArgv(`/output/${NASTY}`, `/dl/${NASTY}`);

    for (const element of argv) {
      // The old code turned ' into the POSIX sequence '\'' and wrapped operands
      // in quotes. Neither may reappear.
      expect(element).not.toContain(`'\\''`);
    }
    expect(argv[1].endsWith(NASTY)).toBe(true);
    expect(argv[2].endsWith(NASTY)).toBe(true);
  });

  it("honors a custom container name in the qualified operand", () => {
    const c = new DockerConnector("my.analysis-box_1");
    expect(c.buildCopyFromContainerArgv("/a", "/b")[1]).toBe("my.analysis-box_1:/a");
  });
});

describe("DockerConnector transfer methods execute without a shell", () => {
  it("readFileToPath runs docker via execFileSync with an argv, never execSync", async () => {
    const c = new DockerConnector("remnux");
    const remote = `/home/remnux/files/output/${NASTY}`;
    const host = `/Users/analyst/dl/${NASTY}`;

    await c.readFileToPath(remote, host);

    expect(execSyncMock).not.toHaveBeenCalled();
    expect(execFileSyncMock).toHaveBeenCalledTimes(1);
    const [bin, argv, opts] = execFileSyncMock.mock.calls[0];
    expect(bin).toBe(RESOLVED_DOCKER);
    expect(argv).toEqual(["cp", `remnux:${remote}`, host]);
    expect(opts).toMatchObject({ shell: false });
  });

  it("writeFileFromPath runs docker via execFileSync with an argv, never execSync", async () => {
    const c = new DockerConnector("remnux");
    const host = `/Users/analyst/staging/${NASTY}`;
    const remote = `/home/remnux/files/samples/${NASTY}`;

    await c.writeFileFromPath(remote, host);

    expect(execSyncMock).not.toHaveBeenCalled();
    const cpCall = execFileSyncMock.mock.calls.find((call) => {
      const argv = call[1] as string[];
      return argv[0] === "cp";
    });
    expect(cpCall).toBeDefined();
    expect(cpCall![0]).toBe(RESOLVED_DOCKER);
    expect(cpCall![1]).toEqual(["cp", host, `remnux:${remote}`]);
    expect(cpCall![2]).toMatchObject({ shell: false });
  });

  // writeFile really creates a host temp file, so its fixture must be a filename
  // Windows will accept — see NASTY_FS_SAFE.
  it("writeFile runs docker via execFileSync with an argv, never execSync", async () => {
    const c = new DockerConnector("remnux");
    const remote = `/home/remnux/files/output/${NASTY_FS_SAFE}`;

    await c.writeFile(remote, Buffer.from("payload"));

    expect(execSyncMock).not.toHaveBeenCalled();
    const cpCall = execFileSyncMock.mock.calls.find((call) => {
      const argv = call[1] as string[];
      return argv[0] === "cp";
    });
    expect(cpCall).toBeDefined();
    expect(cpCall![1][2]).toBe(`remnux:${remote}`);
    expect(cpCall![2]).toMatchObject({ shell: false });
  });

  it("writeFile removes its host temp file and directory after a SUCCESSFUL copy", async () => {
    const c = new DockerConnector("remnux");
    let tempPath: string | undefined;
    execFileSyncMock.mockImplementation((_bin: string, argv: string[]) => {
      if (argv[0] === "cp") {
        tempPath = argv[1];
        // Establish the file was really there at copy time, so the cleanup
        // assertion below cannot pass just because it was never created.
        expect(existsSync(tempPath!)).toBe(true);
      }
    });

    await c.writeFile(`/home/remnux/files/output/${NASTY_FS_SAFE}`, Buffer.from("payload"));

    expect(tempPath).toBeDefined();
    expect(existsSync(tempPath!)).toBe(false);
    expect(existsSync(dirname(tempPath!))).toBe(false);
  });

  it("writeFile removes its host temp file and directory after a FAILED copy", async () => {
    const c = new DockerConnector("remnux");
    let tempPath: string | undefined;
    execFileSyncMock.mockImplementation((_bin: string, argv: string[]) => {
      if (argv[0] === "cp") {
        tempPath = argv[1];
        throw new Error("Error: No such container");
      }
    });

    await expect(
      c.writeFile(`/home/remnux/files/output/${NASTY_FS_SAFE}`, Buffer.from("payload")),
    ).rejects.toThrow(/No such container/);

    expect(tempPath).toBeDefined();
    expect(existsSync(tempPath!)).toBe(false);
    expect(existsSync(dirname(tempPath!))).toBe(false);
  });

  it("writeFile refuses to run docker at all when the container is stopped", async () => {
    containerRunning = false;
    const c = new DockerConnector("remnux");

    await expect(
      c.writeFile("/home/remnux/files/output/a.bin", Buffer.from("payload")),
    ).rejects.toThrow(/not running/);

    expect(execFileSyncMock).not.toHaveBeenCalled();
  });

  it.each([
    ["readFileToPath", (c: InstanceType<typeof DockerConnector>) =>
      c.readFileToPath("/home/remnux/files/output/a.bin", "/Users/analyst/dl/a.bin")],
    ["writeFileFromPath", (c: InstanceType<typeof DockerConnector>) =>
      c.writeFileFromPath("/home/remnux/files/samples/a.bin", "/Users/analyst/a.bin")],
  ])("%s propagates a copy failure instead of swallowing it", async (_name, invoke) => {
    const c = new DockerConnector("remnux");
    execFileSyncMock.mockImplementation((_bin: string, argv: string[]) => {
      if (argv[0] === "cp") throw new Error("Error: No such container:path");
    });

    await expect(invoke(c)).rejects.toThrow(/No such container/);
  });

  it("keeps ownership repair best-effort — a chown failure does not fail the copy", async () => {
    // Base dirs configured, and a non-root exec user, so the mkdir/chown repair
    // path actually runs. Without these it would no-op and this test would pass
    // even if ownership repair were deleted outright.
    const c = new DockerConnector(
      "remnux",
      "remnux",
      "/home/remnux/files/samples",
      "/home/remnux/files/output",
    );
    const attempted: string[][] = [];
    execFileSyncMock.mockImplementation((_bin: string, argv: string[]) => {
      attempted.push(argv);
      if (argv[0] !== "cp") throw new Error("permission denied");
    });

    await expect(
      c.writeFileFromPath("/home/remnux/files/samples/a.bin", "/Users/analyst/a.bin"),
    ).resolves.toBeUndefined();

    // The copy happened, and the repair was genuinely attempted and genuinely failed.
    expect(attempted.some((argv) => argv[0] === "cp")).toBe(true);
    expect(attempted.some((argv) => argv.includes("chown"))).toBe(true);
  });
});

describe("DockerConnector resolves the docker binary rather than letting libuv search", () => {
  it("never passes the bare name 'docker' to execFileSync", async () => {
    // A bare name is resolved by libuv, which searches the process cwd first on
    // Windows. That is the whole attack.
    const c = new DockerConnector("remnux");
    await c.readFileToPath("/output/a.bin", "/host/a.bin");
    await c.writeFileFromPath("/samples/b.bin", "/host/b.bin");
    await c.writeFile("/output/c.bin", Buffer.from("x"));

    // Anti-vacuity: assert calls were actually made before asserting a property
    // of all of them. `[].every(...)` is true, so without this the test would
    // pass having invoked nothing.
    expect(execFileSyncMock.mock.calls.length).toBeGreaterThan(0);
    expect(execFileSyncMock.mock.calls.every((c) => c[0] !== "docker")).toBe(true);
    expect(execFileSyncMock.mock.calls.every((c) => c[0] === RESOLVED_DOCKER)).toBe(
      true,
    );
  });

  it("uses the fully qualified path for the copy", async () => {
    const c = new DockerConnector("remnux");
    await c.readFileToPath("/home/remnux/files/output/a.bin", "/Users/analyst/a.bin");

    expect(execFileSyncMock.mock.calls[0][0]).toBe(RESOLVED_DOCKER);
    expect(resolveExecutableMock).toHaveBeenCalledWith(
      "docker",
      expect.objectContaining({ platform: process.platform }),
    );
  });

  it("resolves once and caches for subsequent calls", async () => {
    const c = new DockerConnector("remnux");
    await c.readFileToPath("/output/a.bin", "/host/a.bin");
    await c.readFileToPath("/output/b.bin", "/host/b.bin");
    await c.readFileToPath("/output/c.bin", "/host/c.bin");

    expect(execFileSyncMock).toHaveBeenCalledTimes(3);
    expect(resolveExecutableMock).toHaveBeenCalledTimes(1);
  });

  it("fails with an actionable error instead of falling back to the bare name", async () => {
    resolveExecutableMock.mockReturnValue(null);
    const c = new DockerConnector("remnux");

    await expect(
      c.readFileToPath("/output/a.bin", "/host/a.bin"),
    ).rejects.toThrow(/Could not find the 'docker' executable in PATH/);

    // The critical half: it did not quietly run something.
    expect(execFileSyncMock).not.toHaveBeenCalled();
  });

  it("a failed resolution is not cached as a success", async () => {
    resolveExecutableMock.mockReturnValueOnce(null);
    const c = new DockerConnector("remnux");

    await expect(c.readFileToPath("/output/a.bin", "/host/a.bin")).rejects.toThrow();

    resolveExecutableMock.mockReturnValue(RESOLVED_DOCKER);
    await expect(
      c.readFileToPath("/output/a.bin", "/host/a.bin"),
    ).resolves.toBeUndefined();
    expect(execFileSyncMock.mock.calls[0][0]).toBe(RESOLVED_DOCKER);
  });
});

describe("class-regression guard: no host-side shell composition in the docker connector", () => {
  const source = readFileSync(
    join(dirname(fileURLToPath(import.meta.url)), "..", "connectors", "docker.ts"),
    "utf-8",
  );

  it("the connector source contains no execSync call", () => {
    // Anti-vacuity control: prove this probe can actually find something before
    // trusting the negative. If the file moved or the read failed, this fails
    // loudly rather than reporting a clean bill of health on an empty string.
    expect(source).toContain("execFileSync");
    expect(source.length).toBeGreaterThan(1000);

    expect(source).not.toMatch(/\bexecSync\b/);
  });

  it("no `docker cp` is built as an interpolated command string", () => {
    // Matches a template literal that both mentions `docker cp` and interpolates
    // a value — i.e. the vulnerable shape, not prose about it in a comment.
    const composedCommand = /`[^`]*docker cp[^`]*\$\{/;

    // Anti-vacuity control: the probe must fire on the shape it is hunting,
    // otherwise "no match" says nothing.
    expect("`docker cp '${a}' '${b}'`").toMatch(composedCommand);

    expect(source).not.toMatch(composedCommand);
  });
});
