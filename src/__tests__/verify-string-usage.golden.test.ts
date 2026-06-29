/**
 * Golden end-to-end test for verify_string_usage against a REAL radare2.
 *
 * Catches radare2-version field drift that the synthetic-JSON unit tests cannot.
 * Uses only the committed synthetic fixture (src/__tests__/fixtures/probe.c) — no
 * private sample, no committed binary. Skipped by default.
 *
 * Run with:
 *   R2_GOLDEN_TEST=1 pnpm exec vitest run src/__tests__/verify-string-usage.golden.test.ts
 *
 * Prerequisites: a running REMnux container (gcc + radare2). Name via CONTAINER
 * (default "remnux").
 */

import { describe, it, expect, beforeAll } from "vitest";
import { execSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { createConnector } from "../connectors/index.js";
import { handleVerifyStringUsage } from "../handlers/verify-string-usage.js";
import { SessionState } from "../state/session.js";
import type { HandlerDeps } from "../handlers/types.js";

interface VerifyEnv {
  success: boolean;
  data: {
    is_code_file?: boolean;
    analysis_complete?: boolean;
    r2_version?: string;
    matches: Array<{ xref_status: string; note: string }>;
  };
}

const CONTAINER = process.env.CONTAINER ?? "remnux";
const SAMPLES_DIR = "/home/remnux/files/samples";
const runGolden = !!process.env.R2_GOLDEN_TEST;

const LIVE = "PROBE_LIVE_STRING_REFERENCED_BY_CODE_0001";
const DEAD = "PROBE_DEAD_STRING_NO_CODE_XREF_0001";

describe.skipIf(!runGolden)("verify_string_usage golden (real radare2)", () => {
  let deps: HandlerDeps;

  beforeAll(async () => {
    const status = execSync(`docker inspect --format='{{.State.Running}}' ${CONTAINER}`, { encoding: "utf-8" }).trim();
    if (status !== "true") throw new Error(`Container ${CONTAINER} is not running`);

    // Compile the committed synthetic source to an ELF inside the container.
    const probeC = readFileSync(fileURLToPath(new URL("./fixtures/probe.c", import.meta.url)), "utf-8");
    execSync(`docker exec -i ${CONTAINER} bash -c 'cat > /tmp/probe.c && gcc -O0 -no-pie -o ${SAMPLES_DIR}/probe /tmp/probe.c'`, {
      input: probeC,
    });

    const connector = await createConnector({ mode: "docker", container: CONTAINER });
    deps = {
      connector,
      config: { samplesDir: SAMPLES_DIR, outputDir: "/home/remnux/files/output", timeout: 300, noSandbox: false, mode: "docker" },
      sessionState: new SessionState(),
    };
  });

  async function verify(query: string): Promise<VerifyEnv> {
    const res = await handleVerifyStringUsage(deps, { file: "probe", query });
    return JSON.parse((res.content as Array<{ text: string }>)[0].text) as VerifyEnv;
  }

  it("a code-referenced string → referenced_from_code", async () => {
    const env = await verify(LIVE);
    expect(env.success).toBe(true);
    expect(env.data.is_code_file).toBe(true);
    expect(env.data.analysis_complete).toBe(true);
    expect(env.data.r2_version).toBeTruthy();
    expect(env.data.matches[0].xref_status).toBe("referenced_from_code");
  });

  it("a present-but-unreferenced string → no_code_xrefs_detected (a real complete-analysis negative)", async () => {
    const env = await verify(DEAD);
    expect(env.data.matches[0].xref_status).toBe("no_code_xrefs_detected");
    expect(env.data.matches[0].note).toContain("This is NOT evidence the string is unused");
  });
});
