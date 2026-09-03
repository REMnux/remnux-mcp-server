/**
 * Builds the copy of a tool's output that is scanned for IOCs, with the tool's own provenance
 * removed. Only the scan copy is affected — the tool output returned to the caller is untouched.
 *
 * Why this exists: capa reports what a detection rule is, who wrote it, which samples it was
 * tested against, and which features it looked for and did NOT find. None of that is evidence
 * about the sample in front of the analyst, and all of it is shaped like an indicator.
 */

/**
 * Metadata field names that commonly appear in tool output (capa, YARA, etc.).
 * Plural forms are listed explicitly because capa uses `authors`, `references`, and `examples`.
 */
const METADATA_FIELDS = [
  "authors?",
  "references?",
  "examples?",
  "namespaces?",
  "description",
  "scopes?",
  "category",
  "severity",
  "version",
  "maintainers?",
  "contributors?",
  "contact",
  "credits",
  "license",
  "copyright",
  "source",
  "created",
  "modified",
].join("|");

/**
 * Metadata line patterns for text output. Matched against the trimmed line.
 */
const METADATA_CONTEXT_PATTERNS = [
  // Standard metadata fields with colon or equals separator (text format)
  // e.g., "author: someone@example.com" or "reference=https://..."
  new RegExp(`^(${METADATA_FIELDS})\\s*[:=]\\s*\\S`, "i"),
  // JSON-format metadata on its own line (pretty-printed JSON)
  // e.g., '"author": "someone@example.com"' or '"reference": "https://..."'
  new RegExp(`^\\s*"(${METADATA_FIELDS})"\\s*:\\s*`, "i"),
  // Comment-prefixed metadata (various languages)
  // e.g., "// author: ..." or "# reference: ..."
  new RegExp(`^(\\/\\/|#|;|--)\\s*(${METADATA_FIELDS})\\s*[:=]`, "i"),
];

/**
 * Filter out lines that appear to be metadata context (author, reference, etc.)
 * to prevent false IOC extraction from tool metadata.
 *
 * @param text - The text to filter
 * @returns Text with metadata lines removed
 */
export function filterMetadataLines(text: string): string {
  return text
    .split("\n")
    .filter((line) => !METADATA_CONTEXT_PATTERNS.some((p) => p.test(line.trim())))
    .join("\n");
}

// ---------------------------------------------------------------------------
// capa
// ---------------------------------------------------------------------------

/** Node budget for the capa walk, so a crafted document cannot make it run unbounded. */
const CAPA_MAX_NODES = 500_000;

/**
 * Feature fields written by the rule author rather than read out of the sample. Everything else
 * on a capa feature node is sample content and is kept.
 *
 *   - `description` annotates the rule;
 *   - `match` names another rule, with that rule's content hash appended;
 *   - `regex` is the pattern the rule searched for, not the text that matched — an alternation
 *     like `good\.com|bad\.com` would otherwise contribute both sides as indicators. The text
 *     that actually matched is in `captures`, which is collected separately;
 *   - `bytes` is the rule's literal byte pattern, and is hash-shaped.
 *
 * Stated as an exclusion rather than an allow-list on purpose. capa's feature vocabulary is long
 * and grows — `import`, `export`, `class`, `namespace`, and `function name` all carry sample
 * content and appear only for particular formats (`import` shows up on .NET binaries, for
 * instance) — so an allow-list silently drops indicators for any type nobody thought to list,
 * while this set is small, verified against real output, and stable.
 */
const CAPA_RULE_AUTHORED_FEATURE_KEYS = new Set([
  "type", "description", "match", "regex", "bytes",
]);

/**
 * Reduce a capa result to the feature values that actually matched in this sample.
 *
 * Four things are deliberately left behind, each of which reached the IOC list before:
 *
 *   - the run metadata and every rule's `meta` and `source` — rule authors, the reference samples
 *     the rule was tested against (`examples`), citations (`references`), and the rule's own YAML;
 *   - the rule names, which are the rule's identity rather than the sample's content;
 *   - the rule-authored feature fields listed above;
 *   - every node whose `success` is false. capa emits its whole feature tree, including the
 *     alternatives it looked for and did NOT find, so an unmatched `string` feature names
 *     something absent from the sample. Reporting one as an indicator inverts its meaning: it is
 *     how "supportxmr.com" and "dwarfpool.com" came to be listed for a sample containing neither.
 *
 * Traversal continues THROUGH an unsuccessful node into its children, because capa serializes
 * every child regardless of the parent's result: a failed `and` can hold a feature that did match
 * and is genuinely present. Only a node's own `success` suppresses its own evidence.
 *
 * Walks iteratively with an explicit stack, so deeply nested input cannot overflow the call stack.
 */
function extractCapaMatchedFeatures(doc: Record<string, unknown>): string {
  const out: string[] = [];
  const stack: unknown[] = [];

  const rules = doc.rules as Record<string, unknown>;
  for (const rule of Object.values(rules)) {
    if (typeof rule === "object" && rule !== null) {
      stack.push((rule as Record<string, unknown>).matches);
    }
  }

  const emitFeature = (feature: unknown) => {
    if (typeof feature !== "object" || feature === null) return;
    for (const [key, featureValue] of Object.entries(feature as Record<string, unknown>)) {
      if (typeof featureValue === "string" && !CAPA_RULE_AUTHORED_FEATURE_KEYS.has(key)) {
        out.push(featureValue);
      }
    }
  };

  let budget = CAPA_MAX_NODES;
  while (stack.length > 0 && budget-- > 0) {
    const value = stack.pop();

    if (Array.isArray(value)) {
      for (const child of value) stack.push(child);
      continue;
    }
    if (typeof value !== "object" || value === null) continue;

    const node = value as Record<string, unknown>;
    // Wrapper objects without the flag (address records) carry no evidence of their own.
    const success = typeof node.success === "boolean" ? node.success : true;

    if (success) {
      const inner = node.node as Record<string, unknown> | undefined;
      emitFeature(inner?.feature);

      // A `count(...)` feature hangs off a range statement rather than appearing as a feature
      // node. A successful range with no locations is a successful count of ZERO — an absence —
      // so its child is only sample content when the node actually matched somewhere.
      const statement = inner?.statement as Record<string, unknown> | undefined;
      if (
        statement?.type === "range" &&
        Array.isArray(node.locations) &&
        node.locations.length > 0
      ) {
        emitFeature(statement.child);
      }

      // `captures` is keyed by the captured substring, which is the text a regex actually matched.
      if (typeof node.captures === "object" && node.captures !== null) {
        for (const captured of Object.keys(node.captures as Record<string, unknown>)) {
          out.push(captured);
        }
      }
    }

    if (Array.isArray(node.children)) stack.push(node.children);
  }

  return out.join("\n");
}

/**
 * Sanitize one tool's output for IOC scanning.
 *
 * Called per tool and BEFORE any size truncation, because capa's JSON is a single document:
 * truncating it first would leave invalid JSON that cannot be parsed or pruned, and the
 * provenance would flow straight through.
 *
 * @param toolName - Registry name of the tool that produced the output (e.g. "capa", "capa-vv")
 * @param text - The tool's raw output
 */
export function sanitizeToolOutputForIOCScan(toolName: string, text: string): string {
  if (toolName === "capa" || toolName.startsWith("capa-")) {
    return sanitizeCapaOutput(text);
  }
  return filterMetadataLines(text);
}

/**
 * Sanitize capa output, in either of the two shapes capa emits.
 *
 * JSON-looking capa output that cannot be structurally handled yields an EMPTY corpus rather than
 * the raw text. capa's `-j` output is a single line beginning with `{`, so the line-based filter
 * cannot remove anything from it: falling back would hand the whole provenance-laden document to
 * the extractor, which is the original defect. A truncated document has already lost its tail;
 * losing the rest costs the matched features, and keeping it costs a wrong IOC list.
 */
function sanitizeCapaOutput(text: string): string {
  const trimmed = text.trim();
  if (!trimmed.startsWith("{")) return filterCapaTextMetadata(text);

  let parsed: unknown;
  try {
    parsed = JSON.parse(trimmed);
  } catch {
    return "";
  }
  if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) return "";
  const doc = parsed as Record<string, unknown>;
  // A run with no matches has an empty `rules` object, which is still a capa document.
  if (typeof doc.rules !== "object" || doc.rules === null) return "";
  return extractCapaMatchedFeatures(doc);
}

/**
 * capa's `-vv` renderer writes metadata column-aligned with no separator character
 * ("author      0x534a@mailbox.org") and wraps long values onto continuation lines indented to
 * the value column. Scoped to capa output, because a bare "source  203.0.113.27" in some other
 * tool's output is a row of data, not provenance.
 */
const CAPA_ALIGNED_METADATA_RE = new RegExp(`^(${METADATA_FIELDS})( {2,})(?=\\S)`, "i");

function filterCapaTextMetadata(text: string): string {
  const out: string[] = [];
  // Column at which the value of the metadata line just dropped began, or -1.
  let continuationColumn = -1;

  for (const line of filterMetadataLines(text).split("\n")) {
    const aligned = CAPA_ALIGNED_METADATA_RE.exec(line);
    if (aligned) {
      continuationColumn = aligned[1].length + aligned[2].length;
      continue;
    }

    if (continuationColumn > 0 && line.trim() !== "") {
      let indent = 0;
      while (indent < line.length && line[indent] === " ") indent++;
      if (indent === continuationColumn) continue;
    }

    continuationColumn = -1;
    out.push(line);
  }

  return out.join("\n");
}
