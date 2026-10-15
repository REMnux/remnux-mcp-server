import { describe, it, expect } from "vitest";
import { extractArchive, getExtractionCommand } from "../archive-extractor.js";
import type { Connector, ExecResult } from "../connectors/index.js";

const ok = (stdout = "", stderr = "", exitCode = 0): ExecResult => ({ stdout, stderr, exitCode });

// 7zz's own wrong-password answer for a header-encrypted RAR5 (measured with 7-Zip 25.01).
const WRONG_PASSWORD = ok("ERROR: /samples/sample.rar\nCannot open encrypted archive. Wrong password?\n", "", 2);

function rarConnector(correctPassword: string, listing = "") {
  const calls: string[][] = [];
  const connector: Connector = {
    async execute(command: string[]): Promise<ExecResult> {
      calls.push(command);
      if (command[0] === "7zz" && command[1] === "l") return listing ? ok(listing) : WRONG_PASSWORD;
      if (command[0] === "7zz" && command[1] === "x") {
        return command.includes(`-p${correctPassword}`) ? ok("Everything is Ok") : WRONG_PASSWORD;
      }
      if (command[0] === "find" && command.includes("-type") && command.includes("f")) return ok("payload.txt\n");
      return ok();
    },
    async executeShell() { return ok(); },
    async writeFile() {},
    async writeFileFromPath() {},
    async readFileToPath() {},
    async disconnect() {},
  };
  return { connector, calls };
}

describe("getExtractionCommand for .rar", () => {
  it("uses 7zz, since REMnux's unrar (unrar-free) rejects -o+ and cannot decrypt", () => {
    expect(getExtractionCommand("rar", "/s/a.rar", "/s/out", "infected")).toEqual(
      ["7zz", "x", "/s/a.rar", "-o/s/out", "-y", "-pinfected"],
    );
  });

  it("passes an empty -p without a password, so 7zz never waits for one", () => {
    expect(getExtractionCommand("rar", "/s/a.rar", "/s/out")).toEqual(
      ["7zz", "x", "/s/a.rar", "-o/s/out", "-y", "-p"],
    );
  });

  it("keeps rejecting option-shaped and shell-shaped passwords", () => {
    expect(() => getExtractionCommand("rar", "/s/a.rar", "/s/out", "-help")).toThrow();
    expect(() => getExtractionCommand("rar", "/s/a.rar", "/s/out", "x;id")).toThrow();
  });
});

describe("extractArchive for .rar", () => {
  it("finds the password through 7zz's wrong-password answers", async () => {
    const { connector, calls } = rarConnector("infected");
    const result = await extractArchive(connector, "/samples/sample.rar", "/samples");
    expect(result.success).toBe(true);
    expect(result.password).toBe("infected");
    expect(result.files).toEqual(["payload.txt"]);
    expect(calls.some((c) => c[0] === "unrar")).toBe(false);
  });

  it("still blocks a traversal entry that 7zz lists for an unencrypted .rar", async () => {
    const { connector } = rarConnector(
      "infected",
      "Path = /samples/sample.rar\nType = Rar5\nPath = ../../../etc/cron.d/evil\n",
    );
    const result = await extractArchive(connector, "/samples/sample.rar", "/samples");
    expect(result.success).toBe(false);
    expect(result.error).toMatch(/path traversal/);
  });

  it("checks the entries of a .rar with encrypted names once a candidate password lists them", async () => {
    const calls: string[][] = [];
    const connector: Connector = {
      async execute(command: string[]): Promise<ExecResult> {
        calls.push(command);
        if (command[0] === "7zz" && command[1] === "l") {
          return command.includes("-pinfected")
            ? ok("Path = /samples/sample.rar\nType = Rar5\nPath = ../../../etc/cron.d/evil\n")
            : WRONG_PASSWORD;
        }
        if (command[0] === "7zz" && command[1] === "x") return command.includes("-pinfected") ? ok("Everything is Ok") : WRONG_PASSWORD;
        return ok();
      },
      async executeShell() { return ok(); },
      async writeFile() {},
      async writeFileFromPath() {},
      async readFileToPath() {},
      async disconnect() {},
    };
    const result = await extractArchive(connector, "/samples/sample.rar", "/samples");
    expect(result.success).toBe(false);
    expect(result.error).toMatch(/path traversal/);
    // Rejected before 7zz extracted anything with the working password.
    expect(calls.some((c) => c[0] === "7zz" && c[1] === "x" && c.includes("-pinfected"))).toBe(false);
  });

  it("does not treat the archive's own path in the listing as a traversal entry", async () => {
    const { connector } = rarConnector("infected", "Path = /samples/sample.rar\nType = Rar5\nPath = payload.txt\n");
    const result = await extractArchive(connector, "/samples/sample.rar", "/samples");
    expect(result.success).toBe(true);
  });
});
