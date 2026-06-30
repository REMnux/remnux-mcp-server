/**
 * Catalog integrity test for data/osint-resources.json — the CI gate for
 * contributor pull requests. ci.yml runs `pnpm test` on every push and PR, so a
 * malformed or non-conforming catalog edit fails here.
 *
 * Validates structure only (the mechanical checks): required fields, enum
 * membership, well-formed https URLs, ISO `last_verified`, and no duplicates.
 * Stability/free-first curation is a human judgment made in review.
 */

import { describe, it, expect } from "vitest";
import { loadOsintCatalogStrict, type OsintResource } from "../osint/index.js";

const ACCESS = new Set(["free", "free_account", "freemium", "paid"]);
const AI_ACCESS = new Set(["api_nokey", "api_key", "web"]);
const DISCLOSURE = new Set(["none", "vendor", "public"]);
const IOC_TYPES = new Set(["hash", "url", "domain", "ip", "family", "host_artifact"]);
const CATEGORIES = new Set([
  "multiscanner", "sandbox", "file_repo", "family_yara", "code_similarity", "url_web",
  "infrastructure", "passive_dns", "registration", "cert_transparency", "aggregator", "community_intel",
  "blocklist", "unpacking",
]);
const ISO_DATE = /^\d{4}-\d{2}-\d{2}$/;

/** Collect every structural violation for a set of entries. Empty array == valid. */
function collectErrors(resources: OsintResource[]): string[] {
  const errors: string[] = [];
  for (const r of resources) {
    const id = (r && r.name) || "(unnamed)";
    if (typeof r.name !== "string" || r.name.length === 0) errors.push(`${id}: missing/empty name`);
    if (typeof r.best_use !== "string" || r.best_use.length === 0) errors.push(`${id}: missing/empty best_use`);
    if (!ACCESS.has(r.access)) errors.push(`${id}: bad access "${r.access}"`);
    if (!AI_ACCESS.has((r as { ai_access?: string }).ai_access ?? "")) {
      errors.push(`${id}: bad ai_access "${(r as { ai_access?: string }).ai_access}"`);
    }
    if (!DISCLOSURE.has(r.query_disclosing)) errors.push(`${id}: bad query_disclosing "${r.query_disclosing}"`);
    if (!DISCLOSURE.has(r.content_disclosing)) errors.push(`${id}: bad content_disclosing "${r.content_disclosing}"`);
    if (typeof r.last_verified !== "string" || !ISO_DATE.test(r.last_verified)) {
      errors.push(`${id}: bad last_verified "${r.last_verified}"`);
    }

    if (!Array.isArray(r.categories) || r.categories.length === 0) {
      errors.push(`${id}: missing categories`);
    } else {
      for (const c of r.categories) if (!CATEGORIES.has(c)) errors.push(`${id}: bad category "${c}"`);
    }

    if (!Array.isArray(r.ioc_types) || r.ioc_types.length === 0) {
      errors.push(`${id}: missing ioc_types`);
    } else {
      for (const t of r.ioc_types) if (!IOC_TYPES.has(t)) errors.push(`${id}: bad ioc_type "${t}"`);
    }

    let parsed: URL | null = null;
    try { parsed = new URL(r.url); } catch { /* leave null */ }
    if (!parsed) errors.push(`${id}: unparseable url "${r.url}"`);
    else if (parsed.protocol !== "https:") errors.push(`${id}: non-https url "${r.url}"`);
  }
  return errors;
}

const catalog = loadOsintCatalogStrict();

describe("osint-resources.json catalog integrity", () => {
  it("has a well-formed top-level shape", () => {
    expect(typeof catalog.version).toBe("string");
    expect(typeof catalog.updated).toBe("string");
    expect(Array.isArray(catalog.resources)).toBe(true);
    expect(catalog.resources.length).toBeGreaterThan(10);
  });

  it("every entry passes structural validation", () => {
    expect(collectErrors(catalog.resources)).toEqual([]);
  });

  it("every schema ioc_type matches at least one resource (no empty slice)", () => {
    const empties = [...IOC_TYPES].filter(
      (t) => catalog.resources.filter((r) => (r.ioc_types as string[]).includes(t)).length === 0,
    );
    expect(empties).toEqual([]);
  });

  it("keeps a healthy floor of keyless (api_nokey) services for agents without keys", () => {
    const noKey = catalog.resources.filter(
      (r) => (r as { ai_access?: string }).ai_access === "api_nokey",
    );
    expect(noKey.length).toBeGreaterThanOrEqual(5);
  });

  it("has no duplicate names or urls", () => {
    const names = catalog.resources.map((r) => r.name.toLowerCase());
    const urls = catalog.resources.map((r) => r.url.toLowerCase().replace(/\/+$/, ""));
    expect(new Set(names).size).toBe(names.length);
    expect(new Set(urls).size).toBe(urls.length);
  });

  it("stays within a sane size bound (catches accidental bloat or truncation)", () => {
    const bytes = Buffer.byteLength(JSON.stringify(catalog), "utf-8");
    expect(bytes).toBeGreaterThan(2_000);
    expect(bytes).toBeLessThan(200_000);
  });

  // Proves the gate actually bites: a known-bad entry must produce violations.
  it("rejects malformed entries", () => {
    const bad = [
      {
        name: "",
        url: "http://insecure.example",
        categories: ["not_a_category"],
        ioc_types: ["not_an_ioc"],
        access: "gratis",
        query_disclosing: "maybe",
        content_disclosing: "maybe",
        best_use: "",
        last_verified: "June 2026",
      } as unknown as OsintResource,
    ];
    const errors = collectErrors(bad);
    expect(errors.length).toBeGreaterThan(0);
    expect(errors.some((e) => e.includes("non-https"))).toBe(true);
    expect(errors.some((e) => e.includes("bad access"))).toBe(true);
    expect(errors.some((e) => e.includes("bad ai_access"))).toBe(true);
    expect(errors.some((e) => e.includes("bad last_verified"))).toBe(true);
  });
});
