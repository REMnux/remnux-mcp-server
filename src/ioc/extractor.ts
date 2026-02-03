/**
 * IOC extraction orchestrator.
 * Combines ioc-extractor (standard types) with custom patterns (registry keys, Windows paths).
 * Deduplicates, scores, and filters noise.
 */

import { extractIOC } from "ioc-extractor";
import { extractCustomPatterns } from "./patterns.js";
import { isNoise, type NoiseFilterOptions } from "./noise.js";
import { scoreIOC } from "./scoring.js";

/** Options for IOC extraction */
export type ExtractOptions = NoiseFilterOptions;

export interface IOCEntry {
  value: string;
  type: string;
  confidence: number;
}

export interface IOCResult {
  iocs: IOCEntry[];
  noise: IOCEntry[];
  summary: {
    total: number;
    noise_filtered: number;
    by_type: Record<string, number>;
    truncated?: string[];
  };
}

/** Map ioc-extractor result keys to our type names. */
const TYPE_MAP: Record<string, string> = {
  ipv4s: "ipv4",
  ipv6s: "ipv6",
  domains: "domain",
  urls: "url",
  emails: "email",
  md5s: "md5",
  sha1s: "sha1",
  sha256s: "sha256",
  sha512s: "sha512",
  ssdeeps: "ssdeep",
  cves: "cve",
  btcs: "btc",
  eths: "eth",
  xmrs: "xmr",
  asns: "asn",
  macAddresses: "mac",
};

const NOISE_THRESHOLD = 0.3;

export function extractIOCs(text: string, options?: ExtractOptions): IOCResult {
  // 1. Standard extraction
  const libResult = extractIOC(text);

  // 2. Collect all entries (value, type) avoiding duplicates
  const seen = new Set<string>();
  const allEntries: IOCEntry[] = [];

  // Track values already classified as hashes to prevent dual-classification as crypto
  const hashValues = new Set<string>();
  const HASH_TYPES = new Set(["md5", "sha1", "sha256", "sha512"]);
  const CRYPTO_TYPES = new Set(["btc", "eth", "xmr"]);

  function add(value: string, type: string) {
    const key = `${type}::${value}`;
    if (seen.has(key)) return;

    // If already classified as a hash, skip crypto classification for same value
    if (CRYPTO_TYPES.has(type) && hashValues.has(value)) return;

    seen.add(key);
    if (HASH_TYPES.has(type)) hashValues.add(value);
    allEntries.push({ value, type, confidence: scoreIOC(value, type) });
  }

  // Standard types from library
  for (const [key, typeName] of Object.entries(TYPE_MAP)) {
    const values = (libResult as unknown as Record<string, string[]>)[key];
    if (values) {
      for (const v of values) {
        add(v, typeName);
      }
    }
  }

  // 3. Custom patterns
  for (const m of extractCustomPatterns(text)) {
    add(m.value, m.type);
  }

  // 4. Split into iocs and noise
  const iocs: IOCEntry[] = [];
  const noise: IOCEntry[] = [];

  for (const entry of allEntries) {
    if (isNoise(entry.value, entry.type, options) || entry.confidence <= NOISE_THRESHOLD) {
      noise.push(entry);
    } else {
      iocs.push(entry);
    }
  }

  // 4b. Cap per-type to prevent hash floods (e.g., 397 MD5s from hex output)
  const MAX_PER_TYPE = 25;
  const byTypeCount: Record<string, number> = {};
  const truncatedTypes: string[] = [];
  const cappedIocs: IOCEntry[] = [];

  for (const entry of iocs) {
    const count = byTypeCount[entry.type] || 0;
    if (count < MAX_PER_TYPE) {
      cappedIocs.push(entry);
    }
    byTypeCount[entry.type] = count + 1;
  }

  for (const [type, count] of Object.entries(byTypeCount)) {
    if (count > MAX_PER_TYPE) {
      truncatedTypes.push(`${type}: showing ${MAX_PER_TYPE} of ${count}`);
    }
  }

  // 5. Build summary
  const byType: Record<string, number> = {};
  for (const entry of cappedIocs) {
    byType[entry.type] = (byType[entry.type] || 0) + 1;
  }

  return {
    iocs: cappedIocs,
    noise,
    summary: {
      total: cappedIocs.length,
      noise_filtered: noise.length,
      by_type: byType,
      ...(truncatedTypes.length > 0 && { truncated: truncatedTypes }),
    },
  };
}
