/**
 * File upload module for REMnux MCP server
 *
 * Allows AI assistants to upload files from the host filesystem to the
 * samples directory via MCP. Reads files locally — no base64 in context.
 */

import { createHash } from "crypto";
import { createReadStream, lstatSync } from "fs";
import { pipeline } from "stream/promises";
import { basename, isAbsolute } from "path";
import type { Connector } from "./connectors/index.js";

// 200MB limit for uploaded files (stat-based check, no in-memory buffering)
const MAX_FILE_SIZE = 200 * 1024 * 1024;

export interface UploadResult {
  success: boolean;
  path?: string;
  size_bytes?: number;
  sha256?: string;
  error?: string;
}

/**
 * Validate filename for security
 * - No path separators (/, \)
 * - No path traversal (..)
 * - No null bytes
 * - Reasonable length
 */
export function validateFilename(filename: string): { valid: boolean; error?: string } {
  if (!filename || filename.length === 0) {
    return { valid: false, error: "Filename cannot be empty" };
  }

  if (filename.length > 255) {
    return { valid: false, error: "Filename too long (max 255 characters)" };
  }

  if (filename.includes("/") || filename.includes("\\")) {
    return { valid: false, error: "Filename cannot contain path separators" };
  }

  if (filename.includes("..")) {
    return { valid: false, error: "Filename cannot contain '..'" };
  }

  if (filename.includes("\0")) {
    return { valid: false, error: "Filename cannot contain null bytes" };
  }

  // Check for shell metacharacters that could cause issues
  if (/[;&|`$\n\r'"<>]/.test(filename)) {
    return { valid: false, error: "Filename contains invalid characters" };
  }

  return { valid: true };
}

/**
 * Validate a host filesystem path for security
 */
export function validateHostPath(hostPath: string): { valid: boolean; error?: string } {
  if (!hostPath || hostPath.length === 0) {
    return { valid: false, error: "host_path cannot be empty" };
  }

  if (!isAbsolute(hostPath)) {
    return { valid: false, error: "host_path must be an absolute path" };
  }

  if (hostPath.includes("\0")) {
    return { valid: false, error: "host_path cannot contain null bytes" };
  }

  // Reject path traversal — always reject ".." components
  if (hostPath.includes("..")) {
    return { valid: false, error: "host_path cannot contain path traversal (..)" };
  }

  // Reject shell metacharacters
  if (/[;&|`$\n\r'"<>]/.test(hostPath)) {
    return { valid: false, error: "host_path contains invalid characters" };
  }

  return { valid: true };
}

/**
 * Upload a file from the host filesystem to the samples directory
 *
 * @param connector - Connector to write files on REMnux
 * @param samplesDir - Base samples directory on REMnux
 * @param hostPath - Absolute path on the host filesystem
 * @param filename - Override filename (defaults to basename of hostPath)
 * @param overwrite - Whether to overwrite if file exists (default: false)
 * @returns Upload result with file path, size, and SHA256 hash
 */
export async function uploadSampleFromHost(
  connector: Connector,
  samplesDir: string,
  hostPath: string,
  filename?: string,
  overwrite: boolean = false
): Promise<UploadResult> {
  // Validate host path
  const pathValidation = validateHostPath(hostPath);
  if (!pathValidation.valid) {
    return { success: false, error: pathValidation.error };
  }

  // Reject symlinks
  let stat;
  try {
    stat = lstatSync(hostPath);
  } catch (_err) {
    return { success: false, error: `File not found: ${hostPath}` };
  }

  if (stat.isSymbolicLink()) {
    return { success: false, error: "Symlinks are not allowed" };
  }

  if (!stat.isFile()) {
    return { success: false, error: "host_path must point to a regular file" };
  }

  // Check file size via stat (no buffering)
  if (stat.size > MAX_FILE_SIZE) {
    const sizeMB = (stat.size / 1024 / 1024).toFixed(0);
    const limitMB = MAX_FILE_SIZE / 1024 / 1024;
    return {
      success: false,
      error:
        `File size (${sizeMB}MB) exceeds the ${limitMB}MB upload limit. ` +
        `For large files such as memory images, mount a host directory into the container instead:\n` +
        `  docker run -v /path/to/evidence:/home/remnux/files/samples/evidence remnux/remnux-distro\n` +
        `Then reference files as: evidence/<filename>`,
    };
  }

  // Determine target filename
  const targetFilename = filename ?? basename(hostPath);

  // Validate target filename
  const filenameValidation = validateFilename(targetFilename);
  if (!filenameValidation.valid) {
    return { success: false, error: filenameValidation.error };
  }

  // Calculate SHA256 hash via streaming
  let sha256: string;
  try {
    const hash = createHash("sha256");
    await pipeline(createReadStream(hostPath), hash);
    sha256 = hash.digest("hex");
  } catch (err) {
    return {
      success: false,
      error: `Failed to read file: ${err instanceof Error ? err.message : "Unknown error"}`,
    };
  }

  // Build full file path
  const filePath = `${samplesDir}/${targetFilename}`;

  // Check if file already exists (unless overwrite is true)
  if (!overwrite) {
    try {
      const checkResult = await connector.execute(["test", "-e", filePath], {
        timeout: 5000,
      });
      if (checkResult.exitCode === 0) {
        return {
          success: false,
          error: "File already exists. Use overwrite=true to replace.",
        };
      }
    } catch {
      // test command failed, file probably doesn't exist
    }
  }

  // Ensure target directory exists (fresh containers may lack it)
  try {
    await connector.execute(["mkdir", "-p", samplesDir], { timeout: 5000 });
  } catch {
    // Ignore — real errors surface in writeFileFromPath
  }

  // Write file using connector's streaming path-based method
  try {
    await connector.writeFileFromPath(filePath, hostPath);
  } catch (err) {
    return {
      success: false,
      error: `Failed to write file: ${err instanceof Error ? err.message : "Unknown error"}`,
    };
  }

  return {
    success: true,
    path: filePath,
    size_bytes: stat.size,
    sha256,
  };
}
