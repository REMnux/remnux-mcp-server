/**
 * Standardized JSON response envelope for all MCP tool handlers.
 *
 * Every tool returns { success, tool, data, metadata } so callers
 * get a predictable shape regardless of which tool was invoked.
 */

import type { ErrorCategory } from "./errors/remnux-error.js";
import { REMnuxError } from "./errors/remnux-error.js";

export interface ToolResponse {
  success: boolean;
  tool: string;
  data: Record<string, unknown>;
  error?: string;
  error_code?: string;
  error_category?: ErrorCategory;
  remediation?: string;
  metadata: {
    elapsed_ms: number;
  };
}

/**
 * Build a success response envelope.
 */
export function formatResponse(
  tool: string,
  data: Record<string, unknown>,
  startTime: number,
): { content: Array<{ type: "text"; text: string }>; isError?: boolean } {
  const envelope: ToolResponse = {
    success: true,
    tool,
    data,
    metadata: { elapsed_ms: Date.now() - startTime },
  };
  const COMPACT_THRESHOLD = 50 * 1024;
  const compact = JSON.stringify(envelope);
  const text = compact.length > COMPACT_THRESHOLD ? compact : JSON.stringify(envelope, null, 2);
  return {
    content: [{ type: "text", text }],
  };
}

/**
 * Build an error response envelope. Sets `isError: true` on the MCP result.
 *
 * When `error` is a REMnuxError, the envelope includes structured fields:
 * error_code, error_category, and remediation.
 */
export function formatError(
  tool: string,
  error: string | REMnuxError,
  startTime: number,
): { content: Array<{ type: "text"; text: string }>; isError: true } {
  const envelope: ToolResponse = {
    success: false,
    tool,
    data: {},
    error: error instanceof REMnuxError ? error.message : error,
    metadata: { elapsed_ms: Date.now() - startTime },
  };

  if (error instanceof REMnuxError) {
    envelope.error_code = error.code;
    envelope.error_category = error.category;
    if (error.remediation) {
      envelope.remediation = error.remediation;
    }
  }

  return {
    content: [{ type: "text", text: JSON.stringify(envelope, null, 2) }],
    isError: true,
  };
}
