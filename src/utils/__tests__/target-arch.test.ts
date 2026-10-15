import { describe, it, expect, vi } from "vitest";
import { normalizeArch, getTargetArch, absenceNoteOnTarget } from "../target-arch.js";
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

const ok = (stdout: string) => async () => ({ stdout, stderr: "", exitCode: 0 });

describe("normalizeArch", () => {
  it("maps dpkg and uname names to Debian names", () => {
    expect(normalizeArch("amd64")).toBe("amd64");
    expect(normalizeArch("x86_64\n")).toBe("amd64");
    expect(normalizeArch("arm64")).toBe("arm64");
    expect(normalizeArch("aarch64")).toBe("arm64");
  });

  it("passes other well-formed names through and rejects junk", () => {
    expect(normalizeArch("armhf")).toBe("armhf");
    expect(normalizeArch("")).toBeNull();
    expect(normalizeArch("bash: dpkg: command not found")).toBeNull();
  });
});

describe("getTargetArch", () => {
  it("reads the architecture on the target, not from the server process", async () => {
    const connector = connectorAnswering(ok("arm64\n"));
    expect(await getTargetArch(connector)).toBe("arm64");
    expect(vi.mocked(connector.executeShell).mock.calls[0][0]).toBe(
      "dpkg --print-architecture 2>/dev/null || uname -m",
    );
  });

  it("caches a successful read per connector and shares an in-flight probe", async () => {
    const connector = connectorAnswering(ok("amd64"));
    const [a, b] = await Promise.all([getTargetArch(connector), getTargetArch(connector)]);
    expect(await getTargetArch(connector)).toBe("amd64");
    expect(a).toBe("amd64");
    expect(b).toBe("amd64");
    expect(connector.executeShell).toHaveBeenCalledTimes(1);
  });

  it("returns null without caching when the probe fails, so the next call retries", async () => {
    const answers = [
      async () => { throw new Error("container not running"); },
      async () => ({ stdout: "", stderr: "", exitCode: 1 }),
      ok("arm64"),
    ];
    const connector = connectorAnswering(() => answers.shift()!());
    expect(await getTargetArch(connector)).toBeNull();
    expect(await getTargetArch(connector)).toBeNull();
    expect(await getTargetArch(connector)).toBe("arm64");
    expect(connector.executeShell).toHaveBeenCalledTimes(3);
  });

  it("keeps a cache per connector", async () => {
    const amd = connectorAnswering(ok("amd64"));
    const arm = connectorAnswering(ok("aarch64"));
    expect(await getTargetArch(amd)).toBe("amd64");
    expect(await getTargetArch(arm)).toBe("arm64");
  });
});

describe("absenceNoteOnTarget", () => {
  it("does not probe the target for a tool that is the same on every architecture", async () => {
    const connector = connectorAnswering(ok("arm64"));
    expect(await absenceNoteOnTarget(connector, "capa")).toBeUndefined();
    expect(connector.executeShell).not.toHaveBeenCalled();
  });

  it("explains an arch-limited tool on arm64 and says nothing on amd64", async () => {
    const arm = connectorAnswering(ok("arm64"));
    const amd = connectorAnswering(ok("amd64"));
    expect(await absenceNoteOnTarget(arm, "tracesc")).toMatch(/^Not included in stock arm64 REMnux \(installed on amd64 only\)\./);
    expect(await absenceNoteOnTarget(amd, "tracesc")).toBeUndefined();
  });

  it("says nothing when the architecture is unknown", async () => {
    const connector = connectorAnswering(async () => ({ stdout: "", stderr: "", exitCode: 127 }));
    expect(await absenceNoteOnTarget(connector, "tracesc")).toBeUndefined();
  });
});
