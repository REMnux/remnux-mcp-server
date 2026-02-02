/**
 * Structured error type for REMnux MCP tools.
 *
 * Carries a machine-readable code, category, and optional
 * remediation hint so callers can programmatically handle errors.
 */

export type ErrorCategory =
  | "validation"
  | "security"
  | "connection"
  | "timeout"
  | "not_found"
  | "tool_failure";

export class REMnuxError extends Error {
  readonly code: string;
  readonly category: ErrorCategory;
  readonly remediation?: string;

  constructor(
    message: string,
    code: string,
    category: ErrorCategory,
    remediation?: string,
  ) {
    super(message);
    this.name = "REMnuxError";
    this.code = code;
    this.category = category;
    this.remediation = remediation;
  }
}
