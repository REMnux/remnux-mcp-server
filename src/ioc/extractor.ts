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

/**
 * Guard against ioc-extractor's quadratic cost on long unbroken runs.
 *
 * extractIOC() is O(n^2) in the length of a single non-whitespace run: measured
 * on 8.1.7, 5KB takes 110ms, 10KB 413ms, 20KB 1.6s and 30KB 3.7s, while 30KB of
 * ordinary whitespace-broken text takes 5ms. analyze_file scans up to
 * IOC_SCAN_CAP (512KB) of tool output PER TOOL, and extraction is synchronous,
 * so one packed sample could freeze the server's event loop for minutes.
 * Base64 payloads, hex dumps, embedded certificates and minified droppers are
 * routine in malware output, so this needs no prompt injection to trigger.
 *
 * Fix: only runs longer than LONG_RUN_THRESHOLD are segmented, into windows of
 * SEGMENT_SIZE that overlap by SEGMENT_OVERLAP. Ordinary text never enters this
 * path and is passed through byte-identical. Overlap keeps any indicator up to
 * SEGMENT_OVERLAP chars intact in at least one window -- sha512 is 128, and
 * nearly every real URL is shorter -- and the caller dedupes by type::value, so
 * a value appearing in two windows collapses to one.
 *
 * Cuts prefer a delimiter within CUT_LOOKBACK chars so that in minified
 * JavaScript, which is one long run that legitimately contains indicators
 * throughout, windows tend to break on token boundaries rather than mid-token.
 *
 * Known limit: an indicator longer than SEGMENT_OVERLAP embedded inside a run
 * longer than the threshold can still be split. Raise SEGMENT_OVERLAP if that
 * is ever observed.
 */
const LONG_RUN_THRESHOLD = 4096;
const SEGMENT_SIZE = 1024;
const SEGMENT_OVERLAP = 256;

/** A `libKey::value` pair as ioc-extractor reports it. */
type LibHit = { key: string; value: string };

/**
 * Is `value` present in `window` at least once WITHOUT touching an artificial
 * edge? An edge is artificial when the window was cut out of a longer run
 * rather than ending at the run's own boundary.
 *
 * Cutting a run necessarily creates token boundaries that did not exist, and
 * those boundaries manufacture indicators: a cut can leave `em.IO` looking like
 * a domain, `FFFF...` (64 chars) like a sha256, or `http://evil.com` like a URL
 * where the original had a longer glued token. Because windows overlap by
 * SEGMENT_OVERLAP, any GENUINE indicator up to that length also appears away
 * from the edges in a neighbouring window, while a manufactured one only ever
 * appears against the cut. That asymmetry is the filter.
 *
 * If the value is not present literally, the library refanged it (`evil[.]com`
 * -> `evil.com`), so accept: a random cut is not going to produce defang
 * markers, and rejecting here would silently drop real defanged indicators.
 */
function appearsAwayFromCut(window: string, value: string, cutLeft: boolean, cutRight: boolean): boolean {
  if (!value) return false;
  let from = 0;
  let foundLiterally = false;
  for (;;) {
    const at = window.indexOf(value, from);
    if (at < 0) break;
    foundLiterally = true;
    const touchesCutStart = at === 0 && cutLeft;
    const touchesCutEnd = at + value.length === window.length && cutRight;
    if (!touchesCutStart && !touchesCutEnd) return true;
    from = at + 1;
  }
  return !foundLiterally;
}

/**
 * Types a cut can fabricate, and which the edge filter therefore polices.
 *
 * Hashes are pure character-class runs of a fixed length, so slicing a longer
 * hex blob can leave exactly 64 hex chars that were never a delimited hash.
 * Bare domains are fragments of dotted identifiers: cutting
 * `System.IO.Compression` can leave `em.IO`.
 *
 * Everything else is deliberately NOT policed. A URL needs a scheme and a valid
 * host, so a cut can only EXPOSE one that is genuinely in the text -- the
 * unsegmented library merely glues the surrounding junk onto the match and
 * reports a dirtier version of the same indicator. Filtering those would drop
 * real C2 URLs, which for a malware-analysis tool is a far worse trade than
 * letting a low-confidence value through to the existing noise and scoring
 * filters.
 */
const CUT_FRAGILE_KEYS = new Set([
  // Fixed-length character-class runs: slicing a longer hex or base58 blob can
  // leave exactly a valid length. Observed on a real sample: a cut isolated a
  // 32-hex GUID fragment that the crypto matcher accepted as a BTC address.
  "md5s",
  "sha1s",
  "sha256s",
  "sha512s",
  "btcs",
  "eths",
  "xmrs",
  "macAddresses",
  // Fragments of dotted identifiers: cutting `System.IO.Compression` -> `em.IO`.
  "domains",
]);

/**
 * Extract from one over-long run through overlapping windows.
 *
 * Cost is linear: each window is at most SEGMENT_SIZE, and there are
 * length / (SEGMENT_SIZE - SEGMENT_OVERLAP) of them, so the library's quadratic
 * behavior is confined to a fixed window size instead of the whole run.
 */
function extractFromLongRun(run: string): LibHit[] {
  const hits: LibHit[] = [];
  const seen = new Set<string>();
  let start = 0;
  for (;;) {
    const end = Math.min(start + SEGMENT_SIZE, run.length);
    const window = run.slice(start, end);
    const cutLeft = start > 0;
    const cutRight = end < run.length;
    const res = extractIOC(window) as unknown as Record<string, string[]>;
    for (const [key, values] of Object.entries(res)) {
      if (!Array.isArray(values)) continue;
      for (const value of values) {
        if (CUT_FRAGILE_KEYS.has(key) && !appearsAwayFromCut(window, value, cutLeft, cutRight)) continue;
        const dedupe = `${key}::${value}`;
        if (seen.has(dedupe)) continue;
        seen.add(dedupe);
        hits.push({ key, value });
      }
    }
    if (end >= run.length) break;
    start = end - SEGMENT_OVERLAP;
  }
  return hits;
}

/** True when `text` contains at least one run past the threshold. */
export function hasLongRun(text: string): boolean {
  if (text.length <= LONG_RUN_THRESHOLD) return false;
  for (const m of text.matchAll(/\S+/g)) {
    if (m[0].length > LONG_RUN_THRESHOLD) return true;
  }
  return false;
}

/**
 * Run the library over `text`, keeping cost linear in the length of any single
 * non-whitespace run and refusing to invent indicators at the cuts.
 *
 * Text with no over-long run takes the ordinary single-call path unchanged.
 */
export function extractLibraryHits(text: string): LibHit[] {
  if (!hasLongRun(text)) {
    const res = extractIOC(text) as unknown as Record<string, string[]>;
    const hits: LibHit[] = [];
    for (const [key, values] of Object.entries(res)) {
      if (Array.isArray(values)) for (const value of values) hits.push({ key, value });
    }
    return hits;
  }

  const hits: LibHit[] = [];
  const longRuns: string[] = [];
  // An indicator cannot span two runs, because runs are separated by
  // whitespace, so pulling the long runs out and scanning them separately
  // cannot split one.
  const withoutLongRuns = text.replace(/\S+/g, (run) => {
    if (run.length <= LONG_RUN_THRESHOLD) return run;
    longRuns.push(run);
    return " ";
  });

  const res = extractIOC(withoutLongRuns) as unknown as Record<string, string[]>;
  for (const [key, values] of Object.entries(res)) {
    if (Array.isArray(values)) for (const value of values) hits.push({ key, value });
  }
  for (const run of longRuns) hits.push(...extractFromLongRun(run));
  return hits;
}

export function extractIOCs(text: string, options?: ExtractOptions): IOCResult {
  // 1. Standard extraction. Windowed over any over-long run so a packed blob
  //    cannot stall the event loop; see extractLibraryHits.
  const libHits = extractLibraryHits(text);

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
  for (const hit of libHits) {
    const typeName = TYPE_MAP[hit.key];
    if (typeName) add(hit.value, typeName);
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
