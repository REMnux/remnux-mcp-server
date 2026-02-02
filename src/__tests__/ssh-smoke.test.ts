/**
 * SSH connector smoke test
 *
 * Manual test that validates the SSH connector against a real REMnux VM or
 * container running sshd. Skipped by default — enable by setting env vars.
 *
 * To run:
 *   SSH_SMOKE_HOST=<host> SSH_SMOKE_USER=<user> npx vitest run src/__tests__/ssh-smoke.test.ts
 *
 * Optional env vars:
 *   SSH_SMOKE_PORT     - SSH port (default: 22)
 *   SSH_SMOKE_PASSWORD - SSH password (default: uses SSH agent)
 */

import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { SSHConnector } from "../connectors/ssh.js";

const host = process.env.SSH_SMOKE_HOST;
const user = process.env.SSH_SMOKE_USER || "remnux";
const port = parseInt(process.env.SSH_SMOKE_PORT || "22", 10);
const password = process.env.SSH_SMOKE_PASSWORD;

const describeOrSkip = host ? describe : describe.skip;

function makeConnector() {
  return new SSHConnector({
    host: host!,
    user,
    port,
    ...(password ? { password } : {}),
  });
}

describeOrSkip("SSH connector smoke test", () => {
  let connector: SSHConnector;

  beforeAll(() => {
    connector = makeConnector();
  });

  afterAll(async () => {
    await connector.disconnect();
  });

  it("connects and runs echo", async () => {
    const result = await connector.execute(["echo", "hello"]);
    expect(result.stdout.trim()).toBe("hello");
    expect(result.exitCode).toBe(0);
  });

  it("runs file --version (validates REMnux tools accessible)", async () => {
    const result = await connector.execute(["file", "--version"]);
    expect(result.stdout).toMatch(/file-/);
    expect(result.exitCode).toBe(0);
  });

  it("handles timeout on long-running command", async () => {
    await expect(
      connector.execute(["sleep", "10"], { timeout: 1000 }),
    ).rejects.toThrow(/timed out/i);
  });

  it("writes a file via writeFile and verifies with cat", async () => {
    const testPath = "/tmp/ssh-smoke-test-" + Date.now();
    const testContent = "smoke-test-data-" + Date.now();

    await connector.writeFile(testPath, Buffer.from(testContent));

    const result = await connector.execute(["cat", testPath]);
    expect(result.stdout.trim()).toBe(testContent);

    // Cleanup
    await connector.execute(["rm", "-f", testPath]);
  });

  it("disconnects cleanly", async () => {
    await connector.disconnect();
    // Re-create for afterAll (connector auto-reconnects on next use)
    connector = makeConnector();
    const result = await connector.execute(["echo", "reconnected"]);
    expect(result.stdout.trim()).toBe("reconnected");
  });
});
