import type { Connector } from "../connectors/index.js";
import { toolCatalog } from "../catalog/index.js";
import { isCommandAbsent, missingCommandsIn } from "./missing-command.js";

/**
 * Architecture of the REMnux system behind a connector, read on that system.
 *
 * This is deliberately not `process.arch`: in docker and ssh modes the server
 * runs elsewhere, and an amd64 container on an arm64 host still has the amd64
 * tool set. Best-effort: `null` when the target cannot report it, and callers
 * treat `null` as "say nothing about architecture", never as a limitation.
 *
 * The result is cached per connector for the life of the process. Concurrent
 * callers share one in-flight probe, and only a successful read is kept, so a
 * transient failure is retried on the next call. Replacing a docker container
 * behind the same name with one of another architecture needs a server restart.
 */
const cache = new WeakMap<Connector, Promise<string | null>>();

/** Map `dpkg --print-architecture` or `uname -m` output to Debian names (amd64, arm64). */
export function normalizeArch(raw: string): string | null {
  const value = raw.trim().toLowerCase();
  if (!/^[a-z0-9_-]{1,32}$/.test(value)) return null;
  if (value === "x86_64" || value === "amd64") return "amd64";
  if (value === "aarch64" || value === "arm64") return "arm64";
  return value;
}

async function readTargetArch(connector: Connector): Promise<string | null> {
  try {
    const result = await connector.executeShell(
      "dpkg --print-architecture 2>/dev/null || uname -m",
      { timeout: 10000 },
    );
    if (result.exitCode !== 0) return null;
    const firstLine = (result.stdout || "").split("\n").map((l) => l.trim()).find(Boolean);
    return firstLine ? normalizeArch(firstLine) : null;
  } catch {
    return null;
  }
}

export function getTargetArch(connector: Connector): Promise<string | null> {
  const cached = cache.get(connector);
  if (cached) return cached;
  const pending = readTargetArch(connector).then((arch) => {
    if (arch === null) cache.delete(connector);
    return arch;
  });
  cache.set(connector, pending);
  return pending;
}

/**
 * The catalog's absence note for `command` on the connector's target, or
 * undefined. Reads the target's architecture only for a command the catalog
 * lists as differing by architecture, so the common case costs no extra call.
 */
export async function absenceNoteOnTarget(
  connector: Connector,
  command: string,
): Promise<string | undefined> {
  if (!toolCatalog.isArchLimited(command)) return undefined;
  return toolCatalog.absenceNote(command, await getTargetArch(connector));
}

/**
 * Absence notes for the commands a shell reported missing in `output`, one per
 * command that stock REMnux lacks on the target's architecture, each prefixed
 * with the command's name. Only commands the shell named count, so a missing
 * helper is not blamed on the tool that called it, and `command -v` must
 * confirm the absence, since the message may come from text a sample supplied.
 */
export async function missingCommandNotes(connector: Connector, output: string): Promise<string[]> {
  const notes: string[] = [];
  for (const name of missingCommandsIn(output)) {
    const note = await absenceNoteOnTarget(connector, name);
    if (note && (await isCommandAbsent(connector, name))) notes.push(`${name}: ${note}`);
  }
  return notes;
}
