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
 * KNOWN LIMITS, so a green run is not read as more than it is:
 *   - Accounting is per RULE, via ruleMatchesEdge (kind-aware, pnpm-equivalent).
 *     Its one gap: when two rules' selectors OVERLAP on the same edge, pnpm
 *     picks one winner but this audit credits every matching rule, so a rule
 *     fully shadowed by a more specific sibling is not reported. A DEAD rule
 *     (no matching edge at all) still is — that is the case worth catching.
 *   - Parent selectors (`parent@range>child`) are matched heuristically on the
 *     parent's name and version; the root importer has neither, so a parent
 *     rule that only a root edge could satisfy is reported as a WARNING, never
 *     a blocking error.
 *   - A `-` removal override deletes the edge Check B looks for, so such a rule
 *     reports as having nothing judgeable.
 *   - The `parent>child` selector is resolved with a heuristic, not pnpm's own
 *     parser. A child whose name starts with a digit, or that carries its own
 *     range, is not parsed correctly.
 *   - peerDependencies are read as declared constraints. That is stricter than
 *     pnpm, which allows peers to be widened.
 * Because of these, this runs as an explicit command and a CI step rather than
 * in `pretest`, where a false positive would block all local testing.
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

/**
 * Extract the package an override actually targets.
 *
 * pnpm supports a parent selector, `parent@range>child`, where the rule governs
 * the CHILD. Reading the parent instead audits the wrong package and silently
 * skips the forced one, so the child wins when `>` is present.
 * https://pnpm.io/settings#overrides
 */
function overrideTargetName(key) {
  const raw = String(key).trim().replace(/^'|'$/g, "");
  // A `>` is only a parent selector when what follows starts a PACKAGE NAME.
  // Ranges contain `>` too: `brace-expansion@>=4.0.0 <5.0.9` must not be read
  // as a selector, or the target parses as '=4.0.0 <5.0.9'.
  let spec = raw;
  for (let i = raw.length - 1; i >= 0; i--) {
    if (raw[i] !== ">") continue;
    const rest = raw.slice(i + 1);
    if (/^[a-zA-Z@]/.test(rest)) spec = rest;
    break;
  }
  spec = spec.trim();
  // Strip a trailing `@range`, keeping a leading `@scope/`.
  const at = spec.lastIndexOf("@");
  return at > 0 ? spec.slice(0, at) : spec;
}

/** pnpm replacement protocols that are not semver ranges at all. */
const PROTOCOL_RE = /^(npm:|workspace:|link:|file:|catalog:|jsr:|\$)/;

/**
 * Classify a replacement value: does it pin an upper bound?
 *
 * Decided from the parsed range, not the string's shape. String shape accepted
 * `>=1 || <2` and `^1 || >=2` -- both upward-unbounded -- because they merely
 * contain `<` or start with `^`. Every comparator set in the union must have a
 * finite upper bound for the whole range to be bounded.
 *
 * Returns { verdict: "bounded" | "unbounded" | "not-semver", detail }.
 */
function classifyReplacement(value) {
  const v = String(value).trim();
  if (v === "") return { verdict: "unbounded", detail: "empty" };
  // `-` removes a dependency; an exact aliased version pins precisely.
  if (v === "-") return { verdict: "bounded", detail: "removal" };
  if (PROTOCOL_RE.test(v)) {
    const aliased = /^npm:.*@(\d[^@]*)$/.exec(v);
    if (aliased && semver.valid(aliased[1])) {
      return { verdict: "bounded", detail: `alias pinned to ${aliased[1]}` };
    }
    return { verdict: "not-semver", detail: `protocol replacement '${v}'` };
  }
  let range;
  try {
    range = new semver.Range(v);
  } catch {
    return { verdict: "not-semver", detail: `unparseable range '${v}'` };
  }
  const everySetBounded = range.set.every((comparators) =>
    comparators.some((c) => c.operator === "<" || c.operator === "<=" || (c.operator === "" && c.semver !== semver.Comparator.ANY))
  );
  return everySetBounded
    ? { verdict: "bounded", detail: "" }
    : { verdict: "unbounded", detail: `no upper bound in '${v}'` };
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
function declaredRangeFrom(parentName, parentVersion, depName, storeEntries) {
  const prefix = `${parentName.replace("/", "+")}@${parentVersion}`;
  let sawManifest = false;
  for (const entry of storeEntries) {
    if (entry !== prefix && !entry.startsWith(`${prefix}_`)) continue;
    const pkg = readPkg(join(PNPM_DIR, entry, "node_modules", parentName, "package.json"));
    if (!pkg) continue;
    sawManifest = true;
    // peerDependencies count: a peer range is a declared constraint the
    // override must still respect. @hono/node-server declares hono ^4 as a
    // PEER, so reading only dependencies left that edge unjudgeable.
    // optionalDependencies win when a manifest names the same dep in both:
    // the optional declaration is the effective one.
    const range =
      pkg.optionalDependencies?.[depName] ??
      pkg.dependencies?.[depName] ??
      pkg.peerDependencies?.[depName];
    if (range) return { range };
  }
  return { range: undefined, why: sawManifest
    ? "parent manifest found but it declares no range for this dependency"
    : "parent manifest not present in the store, so its declared range is unknown" };
}

/**
 * Build the LIVE dependency edges from pnpm-lock.yaml's `snapshots` section.
 *
 * Deliberately not walking node_modules/.pnpm directly: that directory retains
 * orphaned versions from earlier installs, so a store walk reports edges the
 * current lockfile does not resolve. A checker that reports stale findings gets
 * ignored, which is worse than no checker.
 */
/**
 * Parse an override key into pnpm-equivalent matching fields. pnpm applies a
 * `pkg@selector` override to an edge by matching the SELECTOR against the range
 * the parent declares: a semver selector matches when the ranges intersect, a
 * non-semver selector (`latest`, `workspace:*`) matches only on exact spec
 * equality, and a parent selector (`parent@prange>child`) binds the parent,
 * not the child's declared range. Modelling each kind separately keeps a rule
 * from being credited against an edge pnpm would never route to it.
 *   kind: "all"   — bare `pkg`; governs every edge of the target
 *   kind: "range" — semver selector; matches by range intersection
 *   kind: "exact" — non-semver selector; matches by exact declared-spec equality
 *   kind: "parent"— `parent@prange>child`; matches by parent name + version
 */
function parseRuleSelector(key) {
  const raw = String(key).trim().replace(/^'|'$/g, "");
  for (let i = raw.length - 1; i >= 0; i--) {
    if (raw[i] !== ">") continue;
    const rest = raw.slice(i + 1);
    if (/^[a-zA-Z@]/.test(rest)) {
      const parentSpec = raw.slice(0, i).trim();
      const pat = parentSpec.lastIndexOf("@");
      return {
        kind: "parent",
        parentName: pat > 0 ? parentSpec.slice(0, pat) : parentSpec,
        parentRange: (pat > 0 ? parentSpec.slice(pat + 1).trim() : "") || "*",
      };
    }
    break;
  }
  const at = raw.lastIndexOf("@");
  const sel = at > 0 ? raw.slice(at + 1).trim() : "";
  if (!sel) return { kind: "all" };
  if (semver.validRange(sel)) return { kind: "range", range: sel };
  return { kind: "exact", spec: sel };
}

/** Split an edge's `name@version` parent label; `(root)` has no version. */
function splitEdgeParent(parent) {
  if (parent === "(root)") return { name: "(root)", version: null };
  const at = String(parent).lastIndexOf("@");
  return at > 0 ? { name: parent.slice(0, at), version: parent.slice(at + 1) } : { name: parent, version: null };
}

/** Would pnpm route this edge to this rule? Pure — no I/O, for unit testing. */
function ruleMatchesEdge(rule, edge) {
  if (rule.target !== edge.dep) return false;
  switch (rule.selector.kind) {
    case "all":
      return true;
    case "range":
      try { return semver.intersects(rule.selector.range, edge.declared); } catch { return false; }
    case "exact":
      return edge.declared === rule.selector.spec;
    case "parent": {
      const p = splitEdgeParent(edge.parent);
      if (p.name !== rule.selector.parentName) return false;
      if (rule.selector.parentRange === "*" || !semver.validRange(rule.selector.parentRange)) return true;
      try { return p.version != null && semver.satisfies(p.version, rule.selector.parentRange); } catch { return true; }
    }
    default:
      return false;
  }
}

/** Per-rule judged-edge counts. Pure — the seam the dead-sibling control tests. */
function judgeRules(rules, edges) {
  const counts = new Map(rules.map((r) => [r.bare, 0]));
  for (const e of edges) {
    for (const r of rules) {
      if (ruleMatchesEdge(r, e)) counts.set(r.bare, counts.get(r.bare) + 1);
    }
  }
  return counts;
}

function collectEdges(targetNames) {
  const lock = parseYaml(readFileSync(join(ROOT, "pnpm-lock.yaml"), "utf8"));
  const edges = [];
  /** Edges discovered but NOT judgeable. Tracked, never silently dropped. */
  const skipped = [];
  const seen = new Set();
  // Cache the store listing: it was re-read once per edge.
  const storeEntries = existsSync(PNPM_DIR) ? readdirSync(PNPM_DIR) : [];

  // Root importer: take the RESOLVED version from the lockfile importer, not
  // from node_modules, so a stale install cannot make us judge the wrong tree.
  const rootPkg = readPkg(join(ROOT, "package.json")) ?? {};
  const rootDeclared = {
    ...rootPkg.dependencies,
    ...rootPkg.devDependencies,
    ...rootPkg.optionalDependencies,
  };
  const importer = lock.importers?.["."] ?? {};
  const importerResolved = {
    ...importer.dependencies,
    ...importer.devDependencies,
    ...importer.optionalDependencies,
  };
  for (const [depName, declared] of Object.entries(rootDeclared)) {
    if (!targetNames.has(depName)) continue;
    const entry = importerResolved[depName];
    const resolved = entry && typeof entry === "object" ? stripPeers(String(entry.version)) : undefined;
    if (!resolved) {
      skipped.push({ parent: "(root)", dep: depName, why: "no resolution recorded in the lockfile importer" });
      continue;
    }
    edges.push({ parent: "(root)", dep: depName, declared, resolved });
  }

  for (const [rawParent, snap] of Object.entries(lock.snapshots ?? {})) {
    // optionalDependencies are real edges an override still governs.
    const deps = { ...snap?.dependencies, ...snap?.optionalDependencies };
    if (!Object.keys(deps).length) continue;
    const parent = splitSpec(rawParent);
    if (!parent) continue;
    for (const [depName, rawDepVer] of Object.entries(deps)) {
      if (!targetNames.has(depName)) continue;
      const resolved = stripPeers(String(rawDepVer));
      const key = `${parent.name}@${parent.version}|${depName}@${resolved}`;
      if (seen.has(key)) continue;
      seen.add(key);
      const { range: declared, why } = declaredRangeFrom(parent.name, parent.version, depName, storeEntries);
      if (!declared) {
        skipped.push({ parent: `${parent.name}@${parent.version}`, dep: depName, why });
        continue;
      }
      edges.push({ parent: `${parent.name}@${parent.version}`, dep: depName, declared, resolved });
    }
  }
  return { edges, skipped };
}

function audit({ overrides, rawText, inject }) {
  const errors = [];
  const warnings = [];
  const entries = Object.entries(overrides ?? {});
  if (inject?.unbounded) entries.push(["synthetic-pkg@<9.9.9", ">=9.9.9"]);

  // ---- Check A: bounded replacements
  for (const [key, value] of entries) {
    const { verdict, detail } = classifyReplacement(value);
    if (verdict === "bounded") continue;
    if (verdict === "not-semver") {
      // Fail closed: a value this check cannot reason about must not pass
      // silently, or the guarantee is hollow.
      errors.push({
        check: "A",
        rule: `${key}: '${value}'`,
        msg: `replacement cannot be checked for an upper bound (${detail}). Pin it to an explicit version, or extend this audit to understand it.`,
      });
      continue;
    }
    let suggestion = "";
    try {
      const min = semver.minVersion(String(value));
      if (min) suggestion = ` For example '${value} <${semver.major(min) + 1}'.`;
    } catch { /* no suggestion for exotic values */ }
    errors.push({
      check: "A",
      rule: `${key}: '${value}'`,
      msg: `unbounded replacement (${detail}). An open-ended range can cross a major boundary the declaring parent never stated.${suggestion}`,
    });
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
  const targets = new Set(entries.map(([k]) => overrideTargetName(k)));
  const collected = collectEdges(targets);
  const checkedEdges = inject?.outOfRange
    ? [...collected.edges, { parent: "synthetic-parent@1.0.0", dep: [...targets][0] ?? "zod", declared: "^0.0.1", resolved: "9.9.9" }]
    : collected.edges;

  /**
   * Accounting is per RULE, attributed through `ruleMatchesEdge` (the same
   * kind-aware model pnpm uses; see parseRuleSelector). Counting per target
   * package instead (the earlier form) let one live edge mark every rule for
   * that package covered, so a dead sibling rule (two brace-expansion rules,
   * one of which nothing declares into) was invisible.
   * Known limit: when two rules' selectors OVERLAP on the same edge, pnpm
   * applies one winner, but this audit credits every matching rule. A rule
   * fully shadowed by a more specific sibling is therefore not reported; a DEAD
   * rule (no matching edge at all) is — which is the case this control exists
   * to catch.
   */
  const rules = entries.map(([key]) => ({
    bare: String(key).trim().replace(/^'|'$/g, ""),
    target: overrideTargetName(key),
    selector: parseRuleSelector(key),
  }));
  const unjudged = [...collected.skipped];
  const judgeableEdges = [];

  for (const e of checkedEdges) {
    if (!semver.validRange(e.declared) || !semver.valid(e.resolved)) {
      unjudged.push({ parent: e.parent, dep: e.dep, why: `non-semver spec (declared '${e.declared}', resolved '${e.resolved}')` });
      continue;
    }
    judgeableEdges.push(e);
    if (!semver.satisfies(e.resolved, e.declared)) {
      errors.push({
        check: "B",
        rule: `${e.dep}@${e.resolved}`,
        msg: `resolved outside the range its parent declares: ${e.parent} wants '${e.declared}'. An override forced it out of contract.`,
      });
    }
  }

  const judgedPerRule = judgeRules(rules, judgeableEdges);
  const judgedEdges = judgeableEdges.length;
  const kindOf = new Map(rules.map((r) => [r.bare, r.selector.kind]));

  // Fail closed per rule. Previously a new rule whose only edges were optional
  // or whose parent was pruned got ZERO examination while the aggregate edge
  // count stayed non-zero and the gate reported green.
  for (const [rule, count] of judgedPerRule) {
    if (rule.startsWith("synthetic-pkg")) continue;
    if (count === 0) {
      // A parent-selector rule is matched only heuristically (parent name +
      // version; the root importer carries no name/version to match). An
      // unmatched one is therefore a WARNING, never a release-blocking error —
      // the checker must not fail CI on a form it models only approximately.
      if (kindOf.get(rule) === "parent") {
        warnings.push({
          check: "B",
          rule,
          msg: "no edge matched this parent-selector rule under the heuristic parent match; verify by hand that pnpm still applies it (parent selectors are not modelled precisely).",
        });
        continue;
      }
      errors.push({
        check: "B",
        rule,
        msg: "NO dependency edge matches this rule's selector, so nothing was judged under it. The rule may be dead (no parent declares into its range), removed by a `-` override, or its edges unreadable; either way this check proves nothing about it.",
      });
    }
  }
  for (const s of unjudged) {
    warnings.push({ check: "B", rule: `${s.dep} <- ${s.parent}`, msg: `edge not judged: ${s.why}` });
  }

  return {
    errors,
    warnings,
    edgeCount: checkedEdges.length,
    judgedCount: judgedEdges,
    skippedCount: unjudged.length,
    ruleCount: entries.length,
  };
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
  const v = (x) => classifyReplacement(x).verdict;
  expect("classifier accepts genuinely bounded ranges",
    v(">=7.6.5 <8") === "bounded" && v("^4.12.34") === "bounded" && v("~1.2.3") === "bounded"
    && v("1.2.3") === "bounded" && v("1.x") === "bounded");
  expect("classifier rejects open-ended ranges",
    v(">=1.1.13") === "unbounded" && v(">1.0.0") === "unbounded" && v("*") === "unbounded");
  expect("classifier rejects unions with an unbounded arm (string shape accepted these)",
    v(">=1 || <2") === "unbounded" && v("^1 || >=2") === "unbounded");
  expect("classifier flags non-semver protocols instead of crashing",
    v("latest") === "not-semver" && v("workspace:*") === "not-semver" && v("$foo") === "not-semver");
  expect("classifier understands an exact npm alias and a removal",
    v("npm:pkg@1.2.3") === "bounded" && v("-") === "bounded");
  expect("parent selector targets the CHILD, not the parent",
    overrideTargetName("qar@1>zoo") === "zoo" && overrideTargetName("'@scope/a@1>@scope/b'") === "@scope/b");
  expect("a > INSIDE a range is not mistaken for a parent selector",
    overrideTargetName("brace-expansion@>=4.0.0 <5.0.9") === "brace-expansion"
    && overrideTargetName("qs@>6.11.1") === "qs"
    && overrideTargetName("hono@>=4.0.0 <=4.12.11") === "hono");
  expect("plain and scoped keys still resolve to their own name",
    overrideTargetName("qs@<6.15.2") === "qs" && overrideTargetName("'@hono/node-server@<1.19.15'") === "@hono/node-server");
  expect("a rule whose package has no judgeable edge FAILS closed",
    audit({ overrides: { ...overrides, "definitely-not-installed-pkg@<9": "9.0.0" }, rawText })
      .errors.some((e) => e.check === "B" && e.rule === "definitely-not-installed-pkg@<9"));
  // Per-rule, not per-target: a dead sibling of a LIVE rule must still be
  // flagged. Hermetic — fixed synthetic rules and edges, not the live graph,
  // so a future repo change can never make this control spuriously pass or fail.
  const mkRule = (key) => ({ bare: key.replace(/^'|'$/g, ""), target: overrideTargetName(key), selector: parseRuleSelector(key) });
  expect("judgeRules attributes per rule so a dead sibling of a live rule is caught", (() => {
    const rules = [mkRule("foo@^1"), mkRule("foo@^2")]; // ^2 is the dead sibling
    const c = judgeRules(rules, [{ parent: "p@1.0.0", dep: "foo", declared: "^1.1.0", resolved: "1.2.0" }]);
    return c.get("foo@^1") === 1 && c.get("foo@^2") === 0;
  })());
  expect("selector parsing: range, non-semver exact, bare package, parent selector", (() => {
    const range = parseRuleSelector("brace-expansion@<1.1.18");
    const scoped = parseRuleSelector("'@hono/node-server@<1.19.15'");
    const exact = parseRuleSelector("pkg@workspace:*");
    const bare = parseRuleSelector("qs");
    const parent = parseRuleSelector("react@1>loose-envify");
    return range.kind === "range" && range.range === "<1.1.18"
      && scoped.kind === "range" && scoped.range === "<1.19.15"
      && exact.kind === "exact" && exact.spec === "workspace:*"
      && bare.kind === "all"
      && parent.kind === "parent" && parent.parentName === "react" && parent.parentRange === "1";
  })());
  expect("ruleMatchesEdge follows the declared range, exact spec, and parent", (() => {
    const rng = mkRule("brace-expansion@<1.1.18");
    const exact = mkRule("pkg@workspace:*");
    const parent = mkRule("react@^18>loose-envify");
    const edge = (dep, declared, p = "x@1.0.0") => ({ parent: p, dep, declared, resolved: "1.0.0" });
    return ruleMatchesEdge(rng, edge("brace-expansion", "^1.1.7")) && !ruleMatchesEdge(rng, edge("brace-expansion", "^5.0.0"))
      && !ruleMatchesEdge(rng, edge("other", "^1.1.7"))                                  // wrong target
      && ruleMatchesEdge(exact, edge("pkg", "workspace:*")) && !ruleMatchesEdge(exact, edge("pkg", "^1.0.0"))
      && ruleMatchesEdge(parent, edge("loose-envify", "^1.0.0", "react@18.2.0"))         // parent in range
      && !ruleMatchesEdge(parent, edge("loose-envify", "^1.0.0", "react@17.0.0"))        // parent out of range
      && !ruleMatchesEdge(parent, edge("loose-envify", "^1.0.0", "preact@10.0.0"));      // wrong parent
  })());
  expect("every override RULE in this repo had at least one edge judged under its selector", clean.judgedCount > 0
    && !clean.errors.some((e) => e.check === "B" && e.msg.includes("NO dependency edge")));

  console.log(`\nselftest: ${failed === 0 ? "PASS" : `FAIL (${failed})`} — judged ${clean.judgedCount} edges across ${clean.ruleCount} rules, ${clean.skippedCount} unjudged`);
  process.exit(failed === 0 ? 0 : 1);
}

// ------------------------------------------------------------------- main
const rawText = readFileSync(join(ROOT, "pnpm-workspace.yaml"), "utf8");
const overrides = parseYaml(rawText)?.overrides ?? {};
const { errors, warnings, edgeCount, judgedCount, skippedCount, ruleCount } = audit({ overrides, rawText });

for (const w of warnings) console.log(`WARN  [${w.check}] ${w.rule}: ${w.msg}`);
for (const e of errors) console.error(`ERROR [${e.check}] ${e.rule}: ${e.msg}`);

console.log(
  `\naudit-overrides: ${errors.length} error(s), ${warnings.length} warning(s) ` +
  `— ${ruleCount} override rules, ${judgedCount} edges judged, ${skippedCount} unjudged`
);
if (edgeCount === 0) {
  console.error("ERROR: inspected 0 dependency edges. Run `pnpm install` first; a check that cannot see the tree passes vacuously.");
  process.exit(1);
}
process.exit(errors.length === 0 ? 0 : 1);
