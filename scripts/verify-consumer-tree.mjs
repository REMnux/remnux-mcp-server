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
let shapeFailures = 0;

/**
 * Extract advisories from an npm audit v2 `vulnerabilities` object.
 *
 * Fails CLOSED on every shape it cannot account for. An advisory object this
 * parser cannot identify is an ERROR, not an omission: silently ignoring one
 * would let the very finding the gate exists to catch slip through as a clean
 * run. In particular a missing or empty `via` is rejected, not iterated as
 * "nothing here" (the earlier `vuln.via ?? []` did exactly that).
 */
function extractAdvisories(vulnerabilities) {
  if (Array.isArray(vulnerabilities)) {
    throw new Error("npm audit 'vulnerabilities' is an array, not the keyed object a v2 report carries");
  }
  const found = new Map();
  // Every string-only chain must reach an entry that carries an advisory
  // OBJECT. A self-reference or a cycle of string references would otherwise
  // pass every per-entry check and contribute nothing: zero advisories, clean
  // run, fail-open.
  //
  // Reachability is precomputed once as a multi-source reverse BFS: seed the
  // packages that carry a direct advisory object, then propagate backward along
  // reverse `via` edges (child -> the parents that name it). A package reaches
  // an object iff BFS marks it. This is sound on cyclic graphs — a cycle that
  // exits to an object marks every node in the cycle, and a closed cycle marks
  // none — where a forward DFS can wrongly finalize a cycle node as false while
  // an ancestor it depends on is still unresolved. O(V+E), no recursion, so a
  // pathologically deep chain neither overflows the stack nor hangs the gate.
  const reachesSet = new Set();
  const parentsOf = new Map(); // child name -> [parent names that list it in via]
  const queue = [];
  for (const [name, v] of Object.entries(vulnerabilities)) {
    if (!Array.isArray(v?.via)) continue;
    if (v.via.some((x) => typeof x === "object" && x !== null)) { reachesSet.add(name); queue.push(name); }
    for (const x of v.via) {
      if (typeof x !== "string") continue;
      if (!parentsOf.has(x)) parentsOf.set(x, []);
      parentsOf.get(x).push(name);
    }
  }
  for (let i = 0; i < queue.length; i++) {
    for (const parent of parentsOf.get(queue[i]) ?? []) {
      if (!reachesSet.has(parent)) { reachesSet.add(parent); queue.push(parent); }
    }
  }
  const reachesObject = (name) => reachesSet.has(name);
  for (const [pkgName, vuln] of Object.entries(vulnerabilities)) {
    if (!Array.isArray(vuln?.via) || vuln.via.length === 0) {
      throw new Error(
        `vulnerability entry for ${pkgName} has no usable 'via' array, so its advisory cannot be identified: ${JSON.stringify(vuln).slice(0, 200)}`
      );
    }
    for (const via of vuln.via) {
      // A string `via` names another vulnerable package whose own top-level
      // entry carries the advisory object. Require that entry to exist, or the
      // chain ends nowhere and the advisory is lost.
      if (typeof via === "string") {
        if (!Object.prototype.hasOwnProperty.call(vulnerabilities, via)) {
          throw new Error(`via chain for ${pkgName} names '${via}', which has no top-level vulnerability entry`);
        }
        if (!reachesObject(via)) {
          throw new Error(`via chain for ${pkgName} through '${via}' never reaches an advisory object (self-reference or cycle)`);
        }
        continue;
      }
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
  return found;
}

try {
  console.log("packing the tarball that would be published…");
  const packOut = run("npm", ["pack", "--json", "--pack-destination", work], ROOT);
  const tarball = resolve(work, JSON.parse(packOut)[0].filename);

  writeFileSync(join(work, "package.json"), JSON.stringify({ name: "consumer-probe", version: "1.0.0", private: true }, null, 2));
  console.log("installing it the way a consumer would (npm, no lockfile, no overrides)…");
  // --ignore-scripts: this is an advisory inspection of the resolved tree, not
  // a build. It runs inside the publish job, so the freshest unlocked graph
  // must not get to execute lifecycle scripts there.
  run("npm", ["install", "--no-audit", "--no-fund", "--ignore-scripts", tarball], work);

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

  if (selftest) {
    // Parser shape controls. The injected advisory above proves the happy path
    // fires; these prove the parser FAILS CLOSED on the shapes that previously
    // slipped through: `via` missing or empty was iterated as `?? []` and read
    // as "no advisory", which is exactly the silent pass this gate must never
    // produce. Each case is a report fragment the real parser must reject (or,
    // for the last one, accept with exactly one advisory).
    const ghsa = "https://github.com/advisories/GHSA-aaaa-bbbb-cccc";
    const mustThrow = [
      ["via missing", { p: { name: "p", severity: "high" } }],
      ["via empty", { p: { name: "p", severity: "high", via: [] } }],
      ["via not an array", { p: { name: "p", severity: "high", via: "q" } }],
      ["string via naming an absent entry", { p: { name: "p", severity: "high", via: ["ghost"] } }],
      ["object via with no GHSA url or source", { p: { name: "p", severity: "high", via: [{ title: "x" }] } }],
      ["string via self-reference", { p: { name: "p", severity: "high", via: ["p"] } }],
      ["string via cycle with no advisory object", { p: { name: "p", via: ["q"] }, q: { name: "q", via: ["p"] } }],
      ["vulnerabilities as an array", []],
    ];
    for (const [label, fragment] of mustThrow) {
      let threw = false;
      try { extractAdvisories(fragment); } catch { threw = true; }
      console.log(`${threw ? "PASS" : "FAIL"}  parser rejects: ${label}`);
      if (!threw) shapeFailures++;
    }
    let chainOk = false;
    try {
      chainOk = extractAdvisories({ p: { name: "p", via: ["q"] }, q: { name: "q", via: [{ url: ghsa, severity: "high" }] } }).size === 1;
    } catch { chainOk = false; }
    console.log(`${chainOk ? "PASS" : "FAIL"}  parser follows a transitive chain to exactly one advisory`);
    if (!chainOk) shapeFailures++;

    // A pathologically deep but structurally valid string-via chain must not
    // blow the recursion stack (the earlier recursive reachesObject did). 200k
    // links overflow a recursive walk and resolve fine iteratively.
    const deep = {};
    const DEPTH = 200000;
    for (let i = 0; i < DEPTH; i++) {
      deep[`p${i}`] = { name: `p${i}`, via: [i < DEPTH - 1 ? `p${i + 1}` : { url: ghsa, severity: "high" }] };
    }
    let deepOk = false;
    try { deepOk = extractAdvisories(deep).size === 1; } catch { deepOk = false; }
    console.log(`${deepOk ? "PASS" : "FAIL"}  parser walks a ${DEPTH}-link chain without overflowing the stack`);
    if (!deepOk) shapeFailures++;

    // Soundness on a cycle WITH an exit: a→[b,c], b→a, c→advisory. b reaches
    // the advisory through a→c, so the whole graph must resolve (a forward DFS
    // could wrongly finalize b=false while a is still in progress).
    let cycleExitOk = false;
    try {
      cycleExitOk = extractAdvisories({
        a: { name: "a", via: ["b", "c"] },
        b: { name: "b", via: ["a"] },
        c: { name: "c", via: [{ url: ghsa, severity: "high" }] },
      }).size === 1;
    } catch { cycleExitOk = false; }
    console.log(`${cycleExitOk ? "PASS" : "FAIL"}  parser resolves a cycle that exits to an advisory (soundness)`);
    if (!cycleExitOk) shapeFailures++;
  }

  const found = extractAdvisories(report.vulnerabilities);



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
  const ok = failed === 1 && shapeFailures === 0;
  if (ok) {
    console.log("selftest: PASS — the gate rejects an unaccepted advisory and the parser fails closed on malformed entries");
  } else if (shapeFailures > 0) {
    console.log(`selftest: FAIL — ${shapeFailures} parser shape control(s) did not fail closed (listed above)`);
  } else if (failed === 0) {
    console.log("selftest: FAIL — the injected advisory did NOT fail the gate; advisory extraction is broken");
  } else {
    console.log(`selftest: FAIL — ${failed - 1} real unaccepted advisor${failed - 1 === 1 ? "y is" : "ies are"} present in the consumer tree (listed above); the gate itself is working`);
  }
  process.exit(ok ? 0 : 1);
}
process.exit(failed === 0 ? 0 : 1);
