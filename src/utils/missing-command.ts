import type { Connector } from "../connectors/index.js";

const COMMAND_NAME_RE = /^[A-Za-z0-9._+-]+$/;

/**
 * True only when the target positively reports `name` missing (`command -v`
 * exits 1 and prints nothing). A probe that fails, times out, or answers
 * anything else returns false, so callers keep their existing behavior when
 * presence is unknown.
 */
export async function isCommandAbsent(connector: Connector, name: string): Promise<boolean> {
  if (!COMMAND_NAME_RE.test(name)) return false;
  try {
    const result = await connector.executeShell(`command -v ${name}`, { timeout: 10000 });
    return result.exitCode === 1 && !(result.stdout || "").trim() && !(result.stderr || "").trim();
  } catch {
    return false;
  }
}

// The shells' and GNU timeout's own missing-command messages, one per line:
//   bash: line 1: trid: command not found      (bash -c, used by every connector)
//   sh: 1: trid: not found                      (dash)
//   timeout: failed to run command 'trid': No such file or directory
//     (GNU timeout prints curly quotes under a UTF-8 locale)
//   exec: "trid": executable file not found in $PATH   (Docker/OCI)
const MISSING_COMMAND_LINE_RES = [
  /^(?:.*?: )?([^\s:'"‘’]+): (?:command )?not found$/,
  /failed to run command ['‘]([^'’]+)['’]: No such file or directory/,
  /exec: "([^"]+)": executable file not found/,
];

/**
 * Names of the commands that a shell, GNU timeout, or the container runtime
 * reported as missing in `stderr`, as basenames, deduplicated. Only those
 * messages count. Other "not found" text (a missing file, a section, a URL)
 * concerns something else and is ignored.
 */
export function missingCommandsIn(stderr: string): string[] {
  const names = new Set<string>();
  for (const rawLine of (stderr || "").split("\n")) {
    const line = rawLine.trim();
    for (const re of MISSING_COMMAND_LINE_RES) {
      const match = line.match(re);
      if (match) {
        const name = match[1].split("/").pop() ?? "";
        if (COMMAND_NAME_RE.test(name)) names.add(name);
        break;
      }
    }
  }
  return [...names];
}
