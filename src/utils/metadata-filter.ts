/**
 * Filters out lines that contain tool/rule metadata (author, reference, namespace, etc.)
 * to prevent false IOC extraction from capa/YARA rule metadata.
 *
 * This uses a structural approach (detecting metadata line format) rather than
 * domain-specific lists, so it scales without maintenance and works for any tool.
 */

/**
 * Metadata field names that commonly appear in tool output (capa, YARA, etc.)
 */
const METADATA_FIELDS = "author|reference|namespace|description|scope|category|severity|version|maintainer|contributor|contact|source|created|modified";

/**
 * Patterns that identify metadata context lines (author, reference, etc.)
 * These are typically found in capa results, YARA rule output, and similar tools.
 */
const METADATA_CONTEXT_PATTERNS = [
  // Standard metadata fields with colon or equals separator (text format)
  // e.g., "author: someone@example.com" or "reference = https://..."
  new RegExp(`^(${METADATA_FIELDS})\\s*[:=]\\s+`, "i"),
  // JSON-format metadata (capa uses -j for JSON output)
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
