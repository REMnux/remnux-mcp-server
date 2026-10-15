import { describe, it, expect, vi } from "vitest";
import { isCommandAbsent, missingCommandsIn } from "../missing-command.js";
import type { Connector } from "../../connectors/index.js";

function connectorAnswering(answer: () => Promise<{ stdout: string; stderr: string; exitCode: number }>): Connector {
  return {
    execute: vi.fn(),
    executeShell: vi.fn(answer),
    writeFile: vi.fn(),
    writeFileFromPath: vi.fn(),
    readFileToPath: vi.fn(),
    disconnect: vi.fn(),
  };
}

describe("isCommandAbsent", () => {
  it("is true only for command -v's own not-found answer (exit 1, no output)", async () => {
    const c = connectorAnswering(async () => ({ stdout: "", stderr: "", exitCode: 1 }));
    expect(await isCommandAbsent(c, "rar")).toBe(true);
    expect(vi.mocked(c.executeShell).mock.calls[0][0]).toBe("command -v rar");
  });

  it("is false when the command is present", async () => {
    const c = connectorAnswering(async () => ({ stdout: "/usr/bin/rar\n", stderr: "", exitCode: 0 }));
    expect(await isCommandAbsent(c, "rar")).toBe(false);
  });

  it("is false when the probe itself fails, so callers keep their default", async () => {
    const thrown = connectorAnswering(async () => { throw new Error("Command timed out after 10 seconds"); });
    const shellMissing = connectorAnswering(async () => ({
      stdout: "", stderr: "timeout: failed to run command 'bash': No such file or directory", exitCode: 127,
    }));
    const timedOut = connectorAnswering(async () => ({ stdout: "", stderr: "", exitCode: 124 }));
    expect(await isCommandAbsent(thrown, "rar")).toBe(false);
    expect(await isCommandAbsent(shellMissing, "rar")).toBe(false);
    expect(await isCommandAbsent(timedOut, "rar")).toBe(false);
  });

  it("never sends a name that is not a plain command name", async () => {
    const c = connectorAnswering(async () => ({ stdout: "", stderr: "", exitCode: 1 }));
    expect(await isCommandAbsent(c, "rar; id")).toBe(false);
    expect(c.executeShell).not.toHaveBeenCalled();
  });
});

describe("missingCommandsIn", () => {
  it("reads bash's message, as every connector runs commands through bash -c", () => {
    expect(missingCommandsIn("bash: line 1: tracesc: command not found\n")).toEqual(["tracesc"]);
    expect(missingCommandsIn("bash: tracesc: command not found")).toEqual(["tracesc"]);
  });

  it("reads dash's message", () => {
    expect(missingCommandsIn("sh: 1: trid: not found")).toEqual(["trid"]);
  });

  it("reads GNU timeout's message with straight or curly quotes", () => {
    expect(missingCommandsIn("timeout: failed to run command 'rar': No such file or directory")).toEqual(["rar"]);
    expect(missingCommandsIn("timeout: failed to run command ‘rar’: No such file or directory")).toEqual(["rar"]);
  });

  it("reads the container runtime's message and reduces a path to its basename", () => {
    expect(
      missingCommandsIn('OCI runtime exec failed: exec failed: unable to start container process: exec: "/usr/local/bin/thug": executable file not found in $PATH: unknown'),
    ).toEqual(["thug"]);
  });

  it("names only the command the shell reported, not others in a compound command", () => {
    const stderr = "some tool output\nbash: line 1: nosuchtool: command not found\n";
    expect(missingCommandsIn(stderr)).toEqual(["nosuchtool"]);
  });

  it("ignores other 'not found' text and deduplicates", () => {
    expect(missingCommandsIn("section .text not found\nError: file not found in archive\nResource not found")).toEqual([]);
    expect(missingCommandsIn("bash: line 1: trid: command not found\nbash: line 2: trid: command not found")).toEqual(["trid"]);
  });
});
