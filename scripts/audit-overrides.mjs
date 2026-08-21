#!/usr/bin/env node
/**
 * Audits the pnpm `overrides` block in pnpm-workspace.yaml.
 *
 * This repo has hit the same defect four times: an override written as an
 * open-ended replacement (`'>=1.1.13'`) silently carries a package ACROSS a
 * major boundary its parent never declared, and pnpm's first-matching-rule
 * wins, so a later rule intended for the newer line can no longer reach it.
 * Twice that produced advisories the override itself created:
 *
 *   protobufjs        '>=7.5.8'  pushed 7.x -> 8.x  (dockerode declares ^7.3.2)
 *   @hono/node-server '>=1.19.13' pushed 1.x -> 2.x (sdk declares ^1.19.9)
 *   ip-address        '>=10.1.1'  moved the tree INTO the vulnerable window
 *
 * Every one of those was mechanically detectable. Hence this check.
 *
 *   A (error) — every override replacement must carry an upper bound.
 *   B (error) — every package named in overrides must resolve to a version
 *               satisfying the range each declaring parent actually states.
 *   C (warn)  — every override should cite the advisory it exists for.
 *
 * Usage:
 *   node scripts/audit-overrides.mjs
 *   node scripts/audit-overrides.mjs --selftest   # prove the checks can fire
 */
import { readFileSync, readdirSync, existsSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { parse as parseYaml } from "yaml";
import semver from "semver";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const PNPM_DIR = join(ROOT, "node_modules", ".pnpm");

/** Read a package.json, or null if absent/unreadable. */
function readPkg(p) {
  try { return JSON.parse(readFileSync(p, "utf8")); } catch { return null; }
}

/** Override keys look like `name@range` or `'@scope/name@range'`. Extract the name. */
function overrideTargetName(key) {
  const at = key.lastIndexOf("@");
  return at > 0 ? key.slice(0, at) : key;
}

/**
 * Does a replacement value carry an upper bound?
 *
 * Bounded:   '>=7.6.5 <8'  '^4.12.34'  '~1.2.3'  '1.2.3'  '>=1 <2'
 * Unbounded: '>=1.1.13'  '>1.0.0'  '*'
 *
 * A bare `>=`/`>` comparator with no `<` is the exact shape that crossed a
 * major boundary every time this defect appeared.
 */
function isBounded(value) {
  const v = String(value).trim();
  if (v === "*" || v === "") return false;
  if (v.includes("<")) return true;
  // caret, tilde, exact, or hyphen range all bound the upper end
  if (/^[\^~]/.test(v)) return true;
  if (/^\d/.test(v)) return true;
  if (/\s-\s/.test(v)) return true;
  return false;
}

/** Strip a pnpm peer-suffix: `@hono/node-server@2.1.1(hono@4.13.2)` -> `@hono/node-server@2.1.1`. */
function stripPeers(spec) {
  const i = spec.indexOf("(");
  return i < 0 ? spec : spec.slice(0, i);
}

/** Split `name@version` (handles scoped names). */
function splitSpec(spec) {
  const s = stripPeers(spec);
  const at = s.lastIndexOf("@");
  if (at <= 0) return null;
  return { name: s.slice(0, at), version: s.slice(at + 1) };
}

/**
 * Locate a specific parent version's package.json in pnpm's store so we can read
 * the range it DECLARES. The store dir encodes `name@version[_peerhash]`, with
 * `/` in scoped names written as `+`.
 */
function declaredRangeFrom(parentName, parentVersion, depName) {
  if (!existsSync(PNPM_DIR)) return undefined;
  const prefix = `${parentName.replace("/", "+")}@${parentVersion}`;
  for (const entry of readdirSync(PNPM_DIR)) {
    if (entry !== prefix && !entry.startsWith(`${prefix}_`)) continue;
    const pkg = readPkg(join(PNPM_DIR, entry, "node_modules", parentName, "package.json"));
    if (!pkg) continue;
    return pkg.dependencies?.[depName] ?? pkg.optionalDependencies?.[depName];
  }
  return undefined;
}

/**
 * Build the LIVE dependency edges from pnpm-lock.yaml's `snapshots` section.
 *
 * Deliberately not walking node_modules/.pnpm directly: that directory retains
 * orphaned versions from earlier installs, so a store walk reports edges the
 * current lockfile does not resolve. A checker that reports stale findings gets
 * ignored, which is worse than no checker.
 */
function collectEdges(targetNames) {
  const lock = parseYaml(readFileSync(join(ROOT, "pnpm-lock.yaml"), "utf8"));
  const edges = [];
  const seen = new Set();

  // root importer: declared ranges live in our own package.json
  const rootPkg = readPkg(join(ROOT, "package.json")) ?? {};
  const rootDeclared = { ...rootPkg.dependencies, ...rootPkg.devDependencies };
  for (const [depName, declared] of Object.entries(rootDeclared)) {
    if (!targetNames.has(depName)) continue;
    const installed = readPkg(join(ROOT, "node_modules", depName, "package.json"));
    if (installed?.version) {
      edges.push({ parent: "(root)", dep: depName, declared, resolved: installed.version });
    }
  }

  for (const [rawParent, snap] of Object.entries(lock.snapshots ?? {})) {
    const deps = snap?.dependencies;
    if (!deps) continue;
    const parent = splitSpec(rawParent);
    if (!parent) continue;
    for (const [depName, rawDepVer] of Object.entries(deps)) {
      if (!targetNames.has(depName)) continue;
      const resolved = stripPeers(String(rawDepVer));
      const declared = declaredRangeFrom(parent.name, parent.version, depName);
      if (!declared) continue; // parent version not in store (pruned) — cannot judge
      const key = `${parent.name}@${parent.version}|${depName}@${resolved}`;
      if (seen.has(key)) continue;
      seen.add(key);
      edges.push({ parent: `${parent.name}@${parent.version}`, dep: depName, declared, resolved });
    }
  }
  return edges;
}

function audit({ overrides, rawText, inject }) {
  const errors = [];
  const warnings = [];
  const entries = Object.entries(overrides ?? {});
  if (inject?.unbounded) entries.push(["synthetic-pkg@<9.9.9", ">=9.9.9"]);

  // ---- Check A: bounded replacements
  for (const [key, value] of entries) {
    if (!isBounded(value)) {
      errors.push({
        check: "A",
        rule: `${key}: '${value}'`,
        msg: `unbounded replacement. An open-ended '>=' can cross a major boundary the declaring parent never stated. Add an upper bound, e.g. '${value} <${(semver.major(semver.minVersion(String(value)) ?? "0.0.0") || 0) + 1}'.`,
      });
    }
  }

  // ---- Check C: advisory citation (warning only)
  const lines = rawText.split("\n");
  for (const [key] of entries) {
    if (key.startsWith("synthetic-pkg")) continue;
    const bare = key.replace(/^'|'$/g, "");
    const idx = lines.findIndex((l) => l.includes(bare) && !l.trim().startsWith("#"));
    if (idx < 0) continue;
    let cited = /GHSA-[a-z0-9-]+|CVE-\d{4}-\d+/i.test(lines[idx]);
    for (let i = idx - 1; i >= 0 && lines[i].trim().startsWith("#"); i--) {
      if (/GHSA-[a-z0-9-]+|CVE-\d{4}-\d+/i.test(lines[i])) { cited = true; break; }
    }
    if (!cited) warnings.push({ check: "C", rule: bare, msg: "no GHSA/CVE cited; the reason this rule exists is not recorded" });
  }

  // ---- Check B: resolutions stay inside every declaring parent's range
  const targets = new Set(entries.map(([k]) => overrideTargetName(k.replace(/^'|'$/g, ""))));
  const edges = collectEdges(targets);
  const checkedEdges = inject?.outOfRange
    ? [...edges, { parent: "synthetic-parent@1.0.0", dep: [...targets][0] ?? "zod", declared: "^0.0.1", resolved: "9.9.9" }]
    : edges;

  for (const e of checkedEdges) {
    if (!semver.validRange(e.declared)) continue; // workspace:/link:/git specs
    if (!semver.valid(e.resolved)) continue;
    if (!semver.satisfies(e.resolved, e.declared, { includePrerelease: true })) {
      errors.push({
        check: "B",
        rule: `${e.dep}@${e.resolved}`,
        msg: `resolved outside the range its parent declares: ${e.parent} wants '${e.declared}'. An override forced it out of contract.`,
      });
    }
  }

  return { errors, warnings, edgeCount: checkedEdges.length, ruleCount: entries.length };
}

// ---------------------------------------------------------------- selftest
if (process.argv.includes("--selftest")) {
  const rawText = readFileSync(join(ROOT, "pnpm-workspace.yaml"), "utf8");
  const overrides = parseYaml(rawText)?.overrides ?? {};
  let failed = 0;
  const expect = (name, cond) => {
    console.log(`${cond ? "PASS" : "FAIL"}  ${name}`);
    if (!cond) failed++;
  };

  const clean = audit({ overrides, rawText });
  const withUnbounded = audit({ overrides, rawText, inject: { unbounded: true } });
  const withOutOfRange = audit({ overrides, rawText, inject: { outOfRange: true } });

  // Assert on the INJECTED finding specifically. Asserting the clean run has no
  // A/B errors would bake in "the repo is currently clean", which it need not be
  // — and a selftest that fails because a real defect exists is a broken test,
  // not a finding.
  const aCount = (r) => r.errors.filter((e) => e.check === "A").length;
  const bCount = (r) => r.errors.filter((e) => e.check === "B").length;

  expect("check A fires on an injected unbounded rule",
    withUnbounded.errors.some((e) => e.check === "A" && e.rule.includes("synthetic-pkg"))
    && aCount(withUnbounded) === aCount(clean) + 1);
  expect("check B fires on an injected out-of-range resolution",
    withOutOfRange.errors.some((e) => e.check === "B" && e.msg.includes("synthetic-parent"))
    && bCount(withOutOfRange) === bCount(clean) + 1);
  expect("check B actually inspected dependency edges (not vacuously empty)",
    clean.edgeCount > 0);
  expect("isBounded accepts a bounded range", isBounded(">=7.6.5 <8") && isBounded("^4.12.34"));
  expect("isBounded rejects an open-ended range", !isBounded(">=1.1.13") && !isBounded(">1.0.0"));

  console.log(`\nselftest: ${failed === 0 ? "PASS" : `FAIL (${failed})`} — inspected ${clean.edgeCount} edges across ${clean.ruleCount} rules`);
  process.exit(failed === 0 ? 0 : 1);
}

// ------------------------------------------------------------------- main
const rawText = readFileSync(join(ROOT, "pnpm-workspace.yaml"), "utf8");
const overrides = parseYaml(rawText)?.overrides ?? {};
const { errors, warnings, edgeCount, ruleCount } = audit({ overrides, rawText });

for (const w of warnings) console.log(`WARN  [${w.check}] ${w.rule}: ${w.msg}`);
for (const e of errors) console.error(`ERROR [${e.check}] ${e.rule}: ${e.msg}`);

console.log(
  `\naudit-overrides: ${errors.length} error(s), ${warnings.length} warning(s) ` +
  `— ${ruleCount} override rules, ${edgeCount} dependency edges inspected`
);
if (edgeCount === 0) {
  console.error("ERROR: inspected 0 dependency edges. Run `pnpm install` first; a check that cannot see the tree passes vacuously.");
  process.exit(1);
}
process.exit(errors.length === 0 ? 0 : 1);
