/**
 * Unit tests for DockerConnector.buildExecCreateOptions — the pure exec-options
 * builder. No dockerode daemon needed (the Docker client constructs lazily), so
 * this verifies the user/HOME wiring without the stream machinery.
 */

import { describe, it, expect } from "vitest";
import { DockerConnector } from "../connectors/docker.js";

describe("DockerConnector.buildExecCreateOptions", () => {
  it("defaults to running as the remnux user with HOME=/home/remnux", () => {
    const c = new DockerConnector("remnux");
    const opts = c.buildExecCreateOptions(["r2", "-v"]);

    expect(opts.User).toBe("remnux");
    expect(opts.Env).toEqual(["HOME=/home/remnux"]);
    expect(opts.WorkingDir).toBe("/home/remnux");
    expect(opts.Cmd).toEqual(["r2", "-v"]);
    expect(opts.AttachStdout).toBe(true);
    expect(opts.AttachStderr).toBe(true);
  });

  it("honors an explicit cwd over the default home", () => {
    const c = new DockerConnector("remnux");
    const opts = c.buildExecCreateOptions(["ls"], {
      cwd: "/home/remnux/files/samples",
    });

    expect(opts.WorkingDir).toBe("/home/remnux/files/samples");
    // User/Env are unaffected by cwd.
    expect(opts.User).toBe("remnux");
    expect(opts.Env).toEqual(["HOME=/home/remnux"]);
  });

  it("supports a custom exec user and derives root's HOME (differential/root path)", () => {
    const c = new DockerConnector("remnux", "root");
    const opts = c.buildExecCreateOptions(["whoami"]);

    expect(opts.User).toBe("root");
    expect(opts.Env).toEqual(["HOME=/root"]);
    expect(opts.WorkingDir).toBe("/root");
  });

  it("derives /home/<user> HOME for a non-root custom user", () => {
    const c = new DockerConnector("remnux", "analyst");
    const opts = c.buildExecCreateOptions(["id"]);

    expect(opts.User).toBe("analyst");
    expect(opts.Env).toEqual(["HOME=/home/analyst"]);
    expect(opts.WorkingDir).toBe("/home/analyst");
  });

  it("wraps a command with GNU timeout so the container-side process is bounded and killed", () => {
    const c = new DockerConnector("remnux");
    expect(c.buildTimeoutWrappedCommand(["capa", "-j", "x.exe"], 300000)).toEqual([
      "timeout", "-s", "TERM", "-k", "10s", "300s", "capa", "-j", "x.exe",
    ]);
    // sub-second / tiny timeouts floor to at least 1s rather than "0s" (which never fires)
    expect(c.buildTimeoutWrappedCommand(["x"], 500)).toEqual([
      "timeout", "-s", "TERM", "-k", "10s", "1s", "x",
    ]);
  });

  it("uses / (not a fabricated home) for numeric or compound Docker user specs", () => {
    // A valid Docker user value like `uid:gid` or `user:group` must NOT become
    // /home/<uid:gid> (a path that does not exist), which would make docker exec
    // fail before the tool runs.
    for (const u of ["1000:1000", "remnux:remnux", "1000", "0:0"]) {
      const opts = new DockerConnector("c", u).buildExecCreateOptions(["id"]);
      expect(opts.User).toBe(u);
      expect(opts.WorkingDir).toBe("/");
      expect(opts.Env).toEqual(["HOME=/"]);
    }
  });
});

describe("DockerConnector ownership normalization (docker-cp uid/mode fix)", () => {
  it("builds a root chown argv for a copied path under a non-root exec user", () => {
    const c = new DockerConnector(
      "remnux-distro",
      "remnux",
      "/home/remnux/files/samples",
      "/home/remnux/files/output",
    );
    expect(c.buildRootChownArgv("/home/remnux/files/samples/x.bin")).toEqual([
      "exec", "-u", "0", "remnux-distro", "chown", "remnux",
      "/home/remnux/files/samples/x.bin",
    ]);
  });

  it("returns null chown argv when the exec user is root (cp already lands as root)", () => {
    const c = new DockerConnector("remnux-distro", "root", "/s", "/o");
    expect(c.buildRootChownArgv("/s/x")).toBeNull();
  });

  it("builds mkdir+chown argvs for the configured base dirs", () => {
    const c = new DockerConnector(
      "remnux-distro",
      "remnux",
      "/home/remnux/files/samples",
      "/home/remnux/files/output",
    );
    expect(c.buildEnsureDirsArgvs()).toEqual([
      ["exec", "-u", "0", "remnux-distro", "mkdir", "-p",
        "/home/remnux/files/samples", "/home/remnux/files/output"],
      ["exec", "-u", "0", "remnux-distro", "chown", "remnux",
        "/home/remnux/files/samples", "/home/remnux/files/output"],
    ]);
  });

  it("skips dir normalization when exec user is root or no dirs are configured", () => {
    expect(new DockerConnector("c", "root", "/s", "/o").buildEnsureDirsArgvs()).toEqual([]);
    expect(new DockerConnector("c", "remnux").buildEnsureDirsArgvs()).toEqual([]);
  });
});
