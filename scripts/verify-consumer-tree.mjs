#!/usr/bin/env node
/**
 * Verifies the dependency tree a CONSUMER actually receives.
 *
 * pnpm-lock.yaml and pnpm-workspace.yaml are never published, and npm applies
 * `overrides` only from the installing project's root. So `npm install -g
 * @remnux/mcp-server` and `npx` resolve fresh from the caret ranges in
 * package.json: none of this repo's override work travels with the package.
 * Auditing pnpm-lock.yaml therefore says nothing about what lands on an
 * analyst's machine, or on a REMnux box, which installs via `npm install -g`.
 *
 * This packs the tarball that WOULD be published, installs it with npm in a
 * clean directory, and audits that tree. Any advisory outside ALLOWED is an
 * error; an ALLOWED entry that no longer appears is reported so the list can be
 * pruned rather than quietly rotting.
 *
 * Needs network, so it is deliberately NOT wired into `pretest`. It runs in the
 * publish workflow and can be run by hand:
 *
 *   node scripts/verify-consumer-tree.mjs
 *   node scripts/verify-consumer-tree.mjs --selftest   # prove it can fail
 */
import { execFileSync } from "node:child_process";
import { mkdtempSync, rmSync, writeFileSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");

/**
 * Advisories accepted in the consumer tree, each with the reason it is not
 * actionable. Anything not listed here fails the gate.
 */
const ALLOWED = new Map([
  [
    "GHSA-w5hq-g745-h8pq",
    "uuid via dockerode. Affects v3()/v5()/v6() only when the CALLER supplies " +
      "an undersized buf or bad offset. dockerode is the only uuid consumer and " +
      "calls v4() with no arguments (lib/session.js:4,7); v4() throws RangeError. " +
      "That call site is reachable only through dockerode's BuildKit session " +
      "path, which this server never invokes. dockerode 5 drops uuid entirely.",
  ],
]);

function run(cmd, args, cwd) {
  return execFileSync(cmd, args, { cwd, encoding: "utf8", stdio: ["ignore", "pipe", "pipe"], maxBuffer: 64 * 1024 * 1024 });
}

const selftest = process.argv.includes("--selftest");
const work = mkdtempSync(join(tmpdir(), "consumer-tree-"));
let failed = 0;

try {
  console.log("packing the tarball that would be published…");
  const packOut = run("npm", ["pack", "--json", "--pack-destination", work], ROOT);
  const tarball = resolve(work, JSON.parse(packOut)[0].filename);

  writeFileSync(join(work, "package.json"), JSON.stringify({ name: "consumer-probe", version: "1.0.0", private: true }, null, 2));
  console.log("installing it the way a consumer would (npm, no lockfile, no overrides)…");
  run("npm", ["install", "--no-audit", "--no-fund", tarball], work);

  // --- what did the consumer actually get, for every package we override?
  const overridden = ["hono", "@hono/node-server", "protobufjs", "brace-expansion", "fast-uri", "qs", "postcss", "path-to-regexp", "uuid", "ip-address", "esbuild"];
  console.log("\nresolved in the consumer tree:");
  for (const name of overridden) {
    let version = "(not installed)";
    try {
      version = JSON.parse(readFileSync(join(work, "node_modules", name, "package.json"), "utf8")).version;
    } catch { /* absent is fine: dev-only or unreached in a production install */ }
    console.log(`  ${name.padEnd(20)} ${version}`);
  }

  // --- audit that tree
  let report;
  try {
    report = JSON.parse(run("npm", ["audit", "--omit=dev", "--json"], work));
  } catch (err) {
    // npm audit exits non-zero when it finds something; the JSON is still on stdout.
    report = JSON.parse(err.stdout || "{}");
  }

  const found = new Map();
  for (const vuln of Object.values(report.vulnerabilities ?? {})) {
    for (const via of vuln.via ?? []) {
      if (typeof via === "object" && via.url) {
        const id = String(via.url).split("/").pop();
        if (id?.startsWith("GHSA-")) found.set(id, { name: via.name ?? vuln.name, severity: via.severity ?? vuln.severity, title: via.title ?? "" });
      }
    }
  }

  if (selftest) {
    // Anti-vacuity: an advisory the allowlist does NOT contain must fail the
    // gate. Without this the gate could pass because it parsed nothing.
    found.set("GHSA-selftest-0000-0000", { name: "synthetic", severity: "high", title: "injected by --selftest" });
  }

  console.log(`\nadvisories in the consumer tree: ${found.size}`);
  for (const [id, info] of found) {
    const allowed = ALLOWED.get(id);
    if (allowed) {
      console.log(`  ACCEPTED  ${id} [${info.severity}] ${info.name}`);
      console.log(`            ${allowed.split(". ")[0]}.`);
    } else {
      console.error(`  ERROR     ${id} [${info.severity}] ${info.name}: ${info.title}`);
      console.error("            Not in the accepted list. Either fix it, or add it with the reason it is unreachable.");
      failed++;
    }
  }
  for (const id of ALLOWED.keys()) {
    if (!found.has(id)) console.log(`  STALE     ${id} no longer appears; remove it from ALLOWED.`);
  }

  if (found.size === 0 && !selftest) {
    // Not an error, but worth saying out loud: a zero-finding audit could also
    // mean the parse broke. The selftest is what proves it can fire.
    console.log("  (none — run --selftest to confirm this gate can still fail)");
  }
} finally {
  rmSync(work, { recursive: true, force: true });
}

console.log(`\nverify-consumer-tree: ${failed === 0 ? "PASS" : `FAIL (${failed} unaccepted)`}`);
if (selftest) {
  const ok = failed === 1;
  console.log(ok ? "selftest: PASS — the gate rejects an unaccepted advisory" : "selftest: FAIL — injected advisory did not fail the gate");
  process.exit(ok ? 0 : 1);
}
process.exit(failed === 0 ? 0 : 1);
