import type { Connector } from "../connectors/index.js";

/**
 * Cap on what the server will write to the output directory when a tool's
 * output exceeds a response budget (UTF-8 bytes). Bounds disk use per
 * oversized run; larger output is left to the agent's own redirect recipe.
 */
export const MAX_SAVED_OUTPUT_SIZE = 500 * 1024; // 500 KiB

/** A write that has not settled by then is treated as failed (stalled SFTP/docker cp). */
export const DEFAULT_SPILL_TIMEOUT_MS = 30_000;

/** Plain filenames only: no separators, no traversal, no leading dot, no spaces. */
const SAFE_NAME = /^[A-Za-z0-9_][A-Za-z0-9._-]{0,254}$/;

export type SpillResult =
  | { saved: true; path: string }
  | { saved: false; reason: "no_output_dir" | "bad_name" | "too_large" | "write_failed" };

/**
 * Save oversized tool output to `<outputDir>/<name>` so the agent can query
 * the part that did not fit in the response (grep, sed -n, download_file)
 * without re-running the tool. Never throws and never hangs: a failed or
 * stalled write degrades to `saved: false` and the caller falls back to a
 * re-run recipe. `name` must be a plain, caller-sanitized filename (tool name
 * plus sanitized sample name, or tool name plus command hash); anything else
 * is refused here as defense in depth.
 */
export async function saveOversizedOutput(
  connector: Pick<Connector, "writeFile">,
  outputDir: string | undefined,
  name: string,
  text: string,
  opts: { timeoutMs?: number } = {},
): Promise<SpillResult> {
  if (!outputDir) return { saved: false, reason: "no_output_dir" };
  if (!SAFE_NAME.test(name) || name === "." || name === "..") return { saved: false, reason: "bad_name" };
  const bytes = Buffer.from(text, "utf-8");
  if (bytes.length > MAX_SAVED_OUTPUT_SIZE) return { saved: false, reason: "too_large" };
  const path = `${outputDir}/${name}`;
  const timeoutMs = opts.timeoutMs ?? DEFAULT_SPILL_TIMEOUT_MS;
  let timer: ReturnType<typeof setTimeout> | undefined;
  try {
    await Promise.race([
      connector.writeFile(path, bytes),
      new Promise<never>((_, reject) => {
        timer = setTimeout(() => reject(new Error("spill timed out")), timeoutMs);
      }),
    ]);
    return { saved: true, path };
  } catch {
    return { saved: false, reason: "write_failed" };
  } finally {
    if (timer) clearTimeout(timer);
  }
}
