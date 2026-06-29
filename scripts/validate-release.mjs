#!/usr/bin/env node
/**
 * Pre-release live-sample validation sweep.
 *
 * The maintainer's regression gate against REAL samples — it complements the
 * deterministic unit tests + the synthetic-PE golden test in CI by exercising
 * both the NEW tools (verify_string_usage, compare_files, check_behavior_
 * prerequisites) AND the EXISTING ones (get_file_info, analyze_file) on a
 * diverse sample set, so a change cannot silently break either.
 *
 * SAMPLE-AGNOSTIC: hardcodes no sample names, asserts on result SHAPE (valid
 * status enums, well-formed output), and never prints or commits string values,
 * hashes, or IOCs. Real samples come only from the environment.
 *
 * Point REMNUX_SAMPLE_DIR at a directory (inside the container) holding a
 * DIVERSE set — at minimum a packed PE, a .NET assembly, and a multi-stage
 * pair (loader + payload) — so regressions surface across the formats analysts
 * actually see.
 *
 * Usage:
 *   pnpm run build
 *   CONTAINER=remnux REMNUX_SAMPLE_DIR=/home/remnux/files/samples \
 *     node scripts/validate-release.mjs
 */
import { createConnector } from "../dist/connectors/index.js";
import { handleGetFileInfo } from "../dist/handlers/get-file-info.js";
import { handleAnalyzeFile } from "../dist/handlers/analyze-file.js";
import { handleVerifyStringUsage } from "../dist/handlers/verify-string-usage.js";
import { handleCheckBehaviorPrerequisites } from "../dist/handlers/check-behavior-prerequisites.js";
import { handleCompareFiles } from "../dist/handlers/compare-files.js";
import { SessionState } from "../dist/state/session.js";

const CONTAINER = process.env.CONTAINER || "remnux";
const SAMPLES = process.env.REMNUX_SAMPLE_DIR || "/home/remnux/files/samples";
const VALID_XREF = new Set(["referenced_from_code", "no_code_xrefs_detected", "data_only", "unknown"]);
const VALID_CAP = new Set(["capable_statically", "incapable_statically", "possibly_via_dynamic_resolution", "analysis_incomplete", "not_applicable"]);

let pass = 0;
let fail = 0;
const check = (cond, msg) => {
  if (cond) pass++;
  else {
    fail++;
    console.error("  FAIL:", msg);
  }
};

const connector = await createConnector({ mode: "docker", container: CONTAINER });
const deps = {
  connector,
  config: { samplesDir: SAMPLES, outputDir: "/home/remnux/files/output", timeout: 300, noSandbox: false, mode: "docker" },
  sessionState: new SessionState(),
};
const call = async (fn, args) => JSON.parse((await fn(deps, args)).content[0].text);

// Regular files only (skip directories) — names drive the tools, never printed.
const ls = await connector.execute(["find", SAMPLES, "-maxdepth", "1", "-type", "f", "-printf", "%f\\n"], { timeout: 30000 });
const files = (ls.stdout || "").split("\n").map((s) => s.trim()).filter(Boolean);
console.log(`Sweeping ${files.length} sample file(s) from ${SAMPLES} (CONTAINER=${CONTAINER})`);

const pes = [];
for (const f of files) {
  // EXISTING tool — regression smoke (must not break).
  const info = await call(handleGetFileInfo, { file: f });
  check(info.success === true, `get_file_info failed on a sample`);

  // NEW — verify_string_usage: never crashes, only emits valid statuses.
  const vsu = await call(handleVerifyStringUsage, { file: f, query: "Windows" });
  check(vsu.success === true, `verify_string_usage failed on a sample`);
  for (const m of vsu.data?.matches || []) check(VALID_XREF.has(m.xref_status), `invalid xref_status: ${m.xref_status}`);

  const isPe = /\bPE32\+?\b|MS Windows/i.test(info.data?.file_type || "");
  if (isPe) {
    pes.push(f);
    // NEW (Tier B) — check_behavior_prerequisites: valid static_capability values.
    const cbp = await call(handleCheckBehaviorPrerequisites, { file: f, behavior: "clipboard_hijacking" });
    check(cbp.success === true, `check_behavior_prerequisites failed on a sample`);
    for (const r of cbp.data?.results || []) check(VALID_CAP.has(r.static_capability), `invalid static_capability: ${r.static_capability}`);
  }
}

// EXISTING pipeline — analyze_file (quick) regression smoke on the first PE.
if (pes.length >= 1) {
  const af = await call(handleAnalyzeFile, { file: pes[0], depth: "quick" });
  check(af.success === true, "analyze_file (quick) regressed on a sample");
}

// NEW — compare_files structural check on the first two PEs.
if (pes.length >= 2) {
  const cf = await call(handleCompareFiles, { file_a: pes[0], file_b: pes[1], depth: "quick" });
  check(cf.success === true, "compare_files failed");
  check(cf.data?.diff && typeof cf.data.diff.size_delta === "number", "compare_files diff malformed");
  check(Array.isArray(cf.data?.diff?.imports?.added), "compare_files imports diff malformed");
}

await connector.disconnect?.();
console.log(`\n${fail === 0 ? "PASS" : "FAIL"} — ${pass} checks passed, ${fail} failed (${pes.length} PE samples).`);
process.exit(fail === 0 ? 0 : 1);
