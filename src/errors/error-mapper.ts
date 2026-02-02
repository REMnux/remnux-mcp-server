/**
 * Maps raw/unknown errors into structured REMnuxError instances.
 *
 * Catch blocks can call `toREMnuxError(err)` to get a typed error
 * with code, category, and remediation hint.
 */

import { REMnuxError } from "./remnux-error.js";

export function toREMnuxError(raw: unknown, mode?: "docker" | "ssh" | "local"): REMnuxError {
  if (raw instanceof REMnuxError) {
    return raw;
  }

  const msg = raw instanceof Error ? raw.message : String(raw);

  if (/is not running|not running/i.test(msg)) {
    const remediation =
      mode === "ssh" ? "Check SSH connectivity to the REMnux host" :
      mode === "local" ? "Check that the command exists and PATH is correct" :
      "Run `docker start remnux` or check the container status";
    return new REMnuxError(
      msg,
      "CONNECTION_FAILED",
      "connection",
      remediation,
    );
  }

  if (/ECONNREFUSED/i.test(msg)) {
    return new REMnuxError(
      msg,
      "CONNECTION_FAILED",
      "connection",
      "Check SSH host/port configuration",
    );
  }

  if (/timeout/i.test(msg)) {
    return new REMnuxError(
      msg,
      "COMMAND_TIMEOUT",
      "timeout",
      "Increase --timeout or simplify the command",
    );
  }

  return new REMnuxError(msg, "UNKNOWN_ERROR", "tool_failure");
}
