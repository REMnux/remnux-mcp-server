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
});
