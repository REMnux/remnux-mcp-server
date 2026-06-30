/**
 * OSINT resource catalog loader.
 *
 * Loads the contributor-editable data/osint-resources.json (maintained by pull
 * request, validated in CI) and provides slicing helpers for the
 * get_osint_guidance handler. Mirrors the data-file loading pattern in
 * src/catalog/index.ts (data/ at package root, two levels up from dist/osint/),
 * with a module-level memo since the catalog is immutable at runtime.
 *
 * This module reads a bundled JSON file only — no network, no API keys.
 */

import { readFileSync } from "node:fs";
import { resolve, dirname } from "node:path";
import { fileURLToPath } from "node:url";

export type AccessTier = "free" | "free_account" | "freemium" | "paid";
export type DisclosurePosture = "none" | "vendor" | "public";
export type IocType = "hash" | "url" | "domain" | "ip" | "family" | "host_artifact";
/** How directly an AI agent can pull data: clean no-key API, key-gated API, or web/GUI only. */
export type AiAccess = "api_nokey" | "api_key" | "web";

/** Sort priority: keyless programmatic services first (most agent-usable), web/GUI last. */
export const AI_ACCESS_ORDER: Record<AiAccess, number> = { api_nokey: 0, api_key: 1, web: 2 };

export interface OsintResource {
  name: string;
  url: string;
  categories: string[];
  ioc_types: IocType[];
  access: AccessTier;
  ai_access: AiAccess;
  query_disclosing: DisclosurePosture;
  content_disclosing: DisclosurePosture;
  best_use: string;
  caveats?: string;
  stability?: string;
  last_verified: string;
  source_list?: string[];
}

export interface OsintCatalog {
  version: string;
  updated: string;
  resources: OsintResource[];
}

/** The condensed view returned for topic:"all" — keeps the default call cheap. */
export interface CondensedResource {
  name: string;
  ioc_types: IocType[];
  access: AccessTier;
  ai_access: AiAccess;
  query_disclosing: DisclosurePosture;
  content_disclosing: DisclosurePosture;
  best_use: string;
}

/** Absolute path to the bundled catalog (data/ is two levels up from dist/osint/ or src/osint/). */
export function resolveCatalogPath(): string {
  const __dirname = dirname(fileURLToPath(import.meta.url));
  return resolve(__dirname, "../../data/osint-resources.json");
}

/** Load and parse the catalog, throwing on any error. Used by the CI integrity test. */
export function loadOsintCatalogStrict(): OsintCatalog {
  const raw = readFileSync(resolveCatalogPath(), "utf-8");
  return JSON.parse(raw) as OsintCatalog;
}

let cached: OsintCatalog | null = null;

/** Load the catalog with a module-level memo and a graceful fallback so a missing/corrupt file never crashes the server. */
export function loadOsintCatalog(): OsintCatalog {
  if (cached) return cached;
  try {
    const cat = loadOsintCatalogStrict();
    // Order keyless programmatic services first so an agent sees what it can use now.
    cat.resources = [...cat.resources].sort(
      (a, b) => (AI_ACCESS_ORDER[a.ai_access] ?? 9) - (AI_ACCESS_ORDER[b.ai_access] ?? 9),
    );
    cached = cat;
  } catch (err) {
    console.error("WARNING: Failed to load OSINT catalog — get_osint_guidance resources will be empty:", err);
    cached = { version: "0.0.0", updated: "unknown", resources: [] };
  }
  return cached;
}

/** Condense one entry to the fields shown in the topic:"all" index. */
export function condense(r: OsintResource): CondensedResource {
  return {
    name: r.name,
    ioc_types: r.ioc_types,
    access: r.access,
    ai_access: r.ai_access,
    query_disclosing: r.query_disclosing,
    content_disclosing: r.content_disclosing,
    best_use: r.best_use,
  };
}

/** The full catalog condensed (topic:"all"). */
export function condensedCatalog(): CondensedResource[] {
  return loadOsintCatalog().resources.map(condense);
}

/** Full-detail entries whose ioc_types include the given type (ioc_type slice). */
export function resourcesForIocType(iocType: IocType): OsintResource[] {
  return loadOsintCatalog().resources.filter((r) => r.ioc_types.includes(iocType));
}
