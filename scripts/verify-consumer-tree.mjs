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
  // Empty on purpose. GHSA-w5hq-g745-h8pq (uuid via dockerode) was the sole
  // entry and was removed when dockerode 5.0.0 dropped its uuid dependency
  // outright: the edge that carried the advisory no longer exists, so there is
  // nothing left to accept. An empty list is the desired steady state — add an
  // entry only for an advisory that is genuinely unreachable AND unfixable, and
  // delete it the moment the gate reports it STALE.
]);

function run(cmd, args, cwd) {
  return execFileSync(cmd, args, { cwd, encoding: "utf8", stdio: ["ignore", "pipe", "pipe"], maxBuffer: 64 * 1024 * 1024, timeout: 10 * 60 * 1000 });
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
  //
  // npm audit exits non-zero BOTH when it finds vulnerabilities and when it
  // fails outright, and the JSON only lands on stdout in the first case.
  // Treating those the same made this gate fail OPEN: a network error, a killed
  // child, or an unparseable report all produced `{}` and a clean PASS. A
  // release gate that passes because npm never answered is worse than no gate,
  // so every path that is not a well-formed report is now a hard failure.
  let report;
  let rawAudit;
  try {
    rawAudit = run("npm", ["audit", "--omit=dev", "--json"], work);
  } catch (err) {
    rawAudit = err.stdout;
    if (!rawAudit || !String(rawAudit).trim()) {
      throw new Error(
        `npm audit produced no output (exit ${err.status ?? "?"}). Treating as FAILURE, not as a clean tree. stderr: ${String(err.stderr ?? "").slice(0, 400)}`
      );
    }
  }
  try {
    report = JSON.parse(rawAudit);
  } catch {
    throw new Error(`npm audit output is not JSON. Treating as FAILURE. First 400 chars: ${String(rawAudit).slice(0, 400)}`);
  }
  if (report.error) {
    throw new Error(`npm audit reported an error: ${JSON.stringify(report.error).slice(0, 400)}`);
  }
  // Shape check: a v2 report always carries auditReportVersion and a
  // vulnerabilities object. Without them we cannot claim the tree is clean.
  if (report.auditReportVersion !== 2 || typeof report.vulnerabilities !== "object" || report.vulnerabilities === null) {
    throw new Error(
      `npm audit report shape not recognised (auditReportVersion=${report.auditReportVersion}). Treating as FAILURE rather than assuming zero findings.`
    );
  }

  if (selftest) {
    // Inject into the REPORT, before extraction, so the run exercises the
    // parser and the allowlist together. Injecting into the extracted results
    // instead would still pass with a completely broken parser, which is the
    // failure this control exists to rule out.
    report.vulnerabilities["synthetic-selftest-pkg"] = {
      name: "synthetic-selftest-pkg",
      severity: "high",
      via: [{ source: 999999, name: "synthetic-selftest-pkg", severity: "high", title: "injected by --selftest", url: "https://github.com/advisories/GHSA-selftest-0000-0000" }],
    };
  }

  // Extract advisories. An advisory object this parser cannot identify is an
  // ERROR, not an omission: silently ignoring one would let the very finding
  // the gate exists to catch slip through as a clean run.
  const found = new Map();
  for (const [pkgName, vuln] of Object.entries(report.vulnerabilities)) {
    for (const via of vuln.via ?? []) {
      // A string `via` names another vulnerable package, whose own entry is
      // also present at top level, so it needs no handling here.
      if (typeof via === "string") continue;
      if (typeof via !== "object" || via === null) {
        throw new Error(`unrecognised via entry for ${pkgName}: ${JSON.stringify(via).slice(0, 200)}`);
      }
      const id = via.url ? String(via.url).split("/").pop() : undefined;
      const key = id && /^GHSA-/i.test(id) ? id : via.source != null ? `source-${via.source}` : undefined;
      if (!key) {
        throw new Error(
          `advisory for ${pkgName} has neither a GHSA url nor a source id, so it cannot be checked against the accepted list: ${JSON.stringify(via).slice(0, 200)}`
        );
      }
      found.set(key, { name: via.name ?? vuln.name ?? pkgName, severity: via.severity ?? vuln.severity ?? "unknown", title: via.title ?? "" });
    }
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
  // Exactly one failure means the injected advisory is the only one: the gate
  // fires AND the real consumer tree is clean. Distinguish the two failure
  // modes explicitly — this is the release gate's sole run (see publish.yml),
  // so a maintainer reading a blocked release must be able to tell "the gate
  // is broken" from "the gate is working and the tree is dirty".
  const ok = failed === 1;
  if (ok) {
    console.log("selftest: PASS — the gate rejects an unaccepted advisory");
  } else if (failed === 0) {
    console.log("selftest: FAIL — the injected advisory did NOT fail the gate; advisory extraction is broken");
  } else {
    console.log(`selftest: FAIL — ${failed - 1} real unaccepted advisor${failed - 1 === 1 ? "y is" : "ies are"} present in the consumer tree (listed above); the gate itself is working`);
  }
  process.exit(ok ? 0 : 1);
}
process.exit(failed === 0 ? 0 : 1);
