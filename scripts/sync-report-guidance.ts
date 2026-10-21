#!/usr/bin/env tsx
/**
 * Syncs the bundled malware analysis report template + writing guidelines
 * from the canonical public sources on zeltser.com into a committed,
 * generated TypeScript module (src/report/content.generated.ts).
 *
 * Why a generated .ts (not data/)? package.json `files` ships only `dist/`,
 * so a generated module under src/ compiles into dist/ and ships to npm with
 * zero runtime fs/URL/YAML dependency. See Plans/ for the full rationale.
 *
 * The output is DETERMINISTIC: byte-identical upstream content produces a
 * byte-identical file (no wall-clock timestamp), so re-syncing is a clean diff.
 *
 * Run: pnpm run sync:report-guidance
 */

import { writeFileSync, readFileSync, existsSync, mkdirSync } from "fs";
import { resolve, dirname } from "path";
import { fileURLToPath } from "url";
import { createHash } from "node:crypto";
import { parse as parseYaml } from "yaml";

const GUIDELINES_URL =
  "https://zeltser.com/media/docs/malware-analysis-writing-guidelines.yaml";
const TEMPLATE_URL =
  "https://zeltser.com/media/archive/malware-analysis-report-template.md";

// A generic User-Agent — never leak the maintainer's identity in outbound requests.
const USER_AGENT = "research-agent/1.0";

// Top-level YAML keys that are website/MCP plumbing, not report-writing substance.
// Everything else passes through into the digest (robust to future additions).
const EXCLUDE_KEYS = new Set([
  "mcp",
  "crossServerHandoffs",
  "template",
  "companionArticles",
  "relatedArticles",
  "articleKeyPoints",
  "siblingArtifacts",
]);

const SIZE_WARN_BYTES = 100 * 1024;

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const projectRoot = resolve(__dirname, "..");

async function fetchText(url: string): Promise<string> {
  const res = await fetch(url, { headers: { "User-Agent": USER_AGENT } });
  if (!res.ok) {
    throw new Error(`Fetch failed for ${url}: HTTP ${res.status} ${res.statusText}`);
  }
  return res.text();
}

/**
 * Render a fetched value for a `//` comment in the generated module. Every
 * other fetched value is embedded through JSON.stringify as a string literal,
 * but a comment has no literal: a line break or a U+2028/U+2029 line
 * separator in the value would end the comment and the rest would compile as
 * code. JSON.stringify escapes the line break and leaves the separators alone,
 * so keep printable ASCII only. A URL loses nothing by that. The surrounding
 * quotes are dropped so the header reads as before and --check stays stable.
 */
function commentSafe(value: string): string {
  return Array.from(JSON.stringify(value).slice(1, -1))
    .filter((ch) => {
      const code = ch.charCodeAt(0);
      return code >= 0x20 && code < 0x7f;
    })
    .join("");
}

function asString(value: unknown, fallback = ""): string {
  return typeof value === "string" ? value : fallback;
}

async function main() {
  const checkMode = process.argv.includes("--check");
  console.log(`Fetching canonical sources from zeltser.com…${checkMode ? " (--check, no write)" : ""}`);
  const [guidelinesYaml, templateMarkdown] = await Promise.all([
    fetchText(GUIDELINES_URL),
    fetchText(TEMPLATE_URL),
  ]);

  const parsed = parseYaml(guidelinesYaml) as Record<string, unknown>;

  // Guard against a 200-but-not-YAML response (soft 404, CDN interstitial, HTML):
  // a scalar string would otherwise pass through Object.entries() as a per-character
  // "digest" and be written silently. Fail loudly instead.
  if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) {
    throw new Error(
      `Expected a YAML mapping from ${GUIDELINES_URL}, got ${Array.isArray(parsed) ? "array" : typeof parsed}.`,
    );
  }
  if (typeof parsed.version !== "string" || typeof parsed.title !== "string") {
    throw new Error(`${GUIDELINES_URL} is missing expected keys (title/version) — not the guidelines document?`);
  }
  if (!templateMarkdown.includes("Creative Commons Attribution 4.0")) {
    throw new Error(`${TEMPLATE_URL} is missing the expected CC BY 4.0 attribution — not the report template?`);
  }

  // Pull provenance + attribution inputs before stripping plumbing keys.
  const baseUrl = asString(parsed.baseUrl, "https://zeltser.com");
  const articlePath = asString(parsed.articleUrl, "/malware-analysis-report");
  const articleUrl = `${baseUrl}${articlePath}`;
  const version = asString(parsed.version, "unknown");
  const date = asString(parsed.date, "unknown");
  const guidelinesTitle = asString(parsed.title, "Malware Analysis Writing Guidelines");
  const guidelinesLicense = asString(parsed.license, "Copyright (c) Lenny Zeltser");

  const templateBlock = (parsed.template ?? {}) as Record<string, unknown>;
  const templateTitle = asString(templateBlock.title, "Malware Analysis Report Template");
  const templateLicense = asString(templateBlock.license, "CC BY 4.0");
  const templateAuthor = asString(templateBlock.author, asString(parsed.author, "Lenny Zeltser"));

  // Build the digest: parsed YAML minus the plumbing keys.
  const digest: Record<string, unknown> = {};
  for (const [key, value] of Object.entries(parsed)) {
    if (!EXCLUDE_KEYS.has(key)) digest[key] = value;
  }

  const attribution = {
    template: `${templateTitle} — Licensed ${templateLicense} by ${templateAuthor}. ${articleUrl}`,
    guidelines: `${guidelinesTitle} — ${guidelinesLicense}. ${articleUrl}`,
  };

  const sourceMeta = {
    sourceVersion: version,
    sourceDate: date,
    guidelinesUrl: GUIDELINES_URL,
    templateUrl: TEMPLATE_URL,
    fallbackArticleUrl: articleUrl,
  };

  const digestJson = JSON.stringify(digest, null, 2);
  const digestBytes = Buffer.byteLength(digestJson, "utf-8");

  const fileContents = `// GENERATED by scripts/sync-report-guidance.ts — DO NOT EDIT BY HAND.
// Source: ${GUIDELINES_URL}
//         ${TEMPLATE_URL}
// Re-sync with: pnpm run sync:report-guidance
//
// The report template is licensed CC BY 4.0; the writing guidelines are
// © Lenny Zeltser. Both are by Lenny Zeltser — see ${commentSafe(articleUrl)}.

export interface ReportAttribution {
  template: string;
  guidelines: string;
}

export interface ReportSourceMeta {
  sourceVersion: string;
  sourceDate: string;
  guidelinesUrl: string;
  templateUrl: string;
  fallbackArticleUrl: string;
}

/** The malware analysis report template (Markdown, CC BY 4.0, attribution embedded). */
export const REPORT_TEMPLATE: string = ${JSON.stringify(templateMarkdown)};

/** Writing/methodology guidelines digest (canonical YAML minus website/MCP plumbing). */
export const GUIDELINES_DIGEST: Record<string, unknown> = ${digestJson};

export const ATTRIBUTION: ReportAttribution = ${JSON.stringify(attribution, null, 2)};

export const SOURCE_META: ReportSourceMeta = ${JSON.stringify(sourceMeta, null, 2)};
`;

  const outDir = resolve(projectRoot, "src/report");
  const outPath = resolve(outDir, "content.generated.ts");
  const sha256 = createHash("sha256").update(fileContents).digest("hex");

  // --check: verify the committed file matches the canonical sources (drift guard).
  // Manual/maintainer use only — never wired into CI, which must build offline.
  if (checkMode) {
    if (!existsSync(outPath)) {
      throw new Error(`--check: ${outPath} is missing. Run 'pnpm run sync:report-guidance'.`);
    }
    if (readFileSync(outPath, "utf-8") !== fileContents) {
      throw new Error(
        `--check: ${outPath} is out of date with the canonical sources. ` +
          `Run 'pnpm run sync:report-guidance' and commit the result.`,
      );
    }
    console.log(`✅ ${outPath} is up to date (source ${version}, sha256 ${sha256.slice(0, 16)}…)`);
    return;
  }

  mkdirSync(outDir, { recursive: true });
  writeFileSync(outPath, fileContents, "utf-8");

  console.log(`✅ Wrote ${outPath}`);
  console.log(`   source version: ${version} (${date})`);
  console.log(`   template: ${Buffer.byteLength(templateMarkdown, "utf-8")} bytes`);
  console.log(`   guidelines digest: ${digestBytes} bytes`);
  console.log(`   sha256: ${sha256}`);
  console.log("   Content was fetched from the network — review the git diff before committing.");
  if (digestBytes > SIZE_WARN_BYTES) {
    console.warn(
      `⚠️  Guidelines digest is ${digestBytes} bytes (> ${SIZE_WARN_BYTES}). ` +
        `Consider whether the digest should narrow before this lands in get_report_guidance.`,
    );
  }
}

main().catch((err) => {
  console.error(`❌ sync-report-guidance failed: ${err instanceof Error ? err.message : String(err)}`);
  process.exit(1);
});
