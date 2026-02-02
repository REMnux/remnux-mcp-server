import type { HandlerDeps } from "./types.js";
import type { DownloadFromUrlArgs } from "../schemas/tools.js";
import { validateFilename } from "../file-upload.js";
import { formatResponse, formatError } from "../response.js";
import { REMnuxError } from "../errors/remnux-error.js";
import { toREMnuxError } from "../errors/error-mapper.js";
import { posix } from "path";

/** Max download size (200MB) */
const MAX_FILESIZE = 200 * 1024 * 1024;

/** Max redirects */
const MAX_REDIRS = 10;

/** Default thug timeout (seconds) */
const DEFAULT_THUG_TIMEOUT = 120;

/** Curl exit code descriptions */
const CURL_ERRORS: Record<number, string> = {
  6: "Could not resolve host (DNS failure)",
  7: "Failed to connect to host",
  22: "HTTP error (4xx/5xx response)",
  28: "Download timed out",
  35: "SSL/TLS handshake failed",
  47: "Too many redirects",
  56: "Failure receiving data (connection reset)",
  63: "File exceeds maximum size limit (200MB)",
};

/**
 * Validate a URL for download: must be http(s), no control chars, no single quotes.
 */
export function validateUrl(url: string): { valid: boolean; error?: string } {
  let parsed: URL;
  try {
    parsed = new URL(url);
  } catch {
    return { valid: false, error: "Invalid URL" };
  }

  if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
    return { valid: false, error: `Unsupported protocol: ${parsed.protocol} (only http and https allowed)` };
  }

  // Reject control characters and single quotes (shell injection vectors)
  if (/[\x00-\x1f']/.test(url)) {
    return { valid: false, error: "URL contains invalid characters (control chars or single quotes)" };
  }

  return { valid: true };
}

/**
 * Validate a single HTTP header string.
 * Must be "Name: value" with no injection characters.
 */
export function validateHeader(header: string): { valid: boolean; error?: string } {
  // Reject newlines, carriage returns, null bytes, single quotes first (security)
  if (/[\x00\n\r']/.test(header)) {
    return { valid: false, error: `Header contains invalid characters: "${header}"` };
  }

  // Must match "HeaderName: value"
  if (!/^[\w-]+:\s*.+$/.test(header)) {
    return { valid: false, error: `Invalid header format: "${header}". Expected "Name: value"` };
  }

  return { valid: true };
}

/**
 * Derive a filename from a URL path.
 * Falls back to "downloaded_sample" if no basename can be extracted.
 */
export function deriveFilename(url: string): string {
  try {
    const parsed = new URL(url);
    const base = posix.basename(parsed.pathname);
    // Filter out empty strings and index-like names
    if (base && base !== "/" && base !== "." && !base.startsWith("?")) {
      // Strip query params that might be part of the basename
      const cleaned = base.split("?")[0] || "downloaded_sample";
      try {
        return decodeURIComponent(cleaned);
      } catch {
        return cleaned;
      }
    }
  } catch {
    // fall through
  }
  return "downloaded_sample";
}

export async function handleDownloadFromUrl(
  deps: HandlerDeps,
  args: DownloadFromUrlArgs,
) {
  const startTime = Date.now();
  const { connector, config } = deps;
  const method = args.method ?? "curl";

  try {
    // Validate URL
    const urlValidation = validateUrl(args.url);
    if (!urlValidation.valid) {
      return formatError("download_from_url", new REMnuxError(
        urlValidation.error!,
        "INVALID_URL",
        "validation",
        "Provide a valid http:// or https:// URL",
      ), startTime);
    }

    // Validate headers if provided
    const headers = args.headers ?? [];
    for (const h of headers) {
      const hv = validateHeader(h);
      if (!hv.valid) {
        return formatError("download_from_url", new REMnuxError(
          hv.error!,
          "INVALID_HEADER",
          "validation",
          "Headers must be 'Name: value' format without control characters or single quotes",
        ), startTime);
      }
    }

    // Determine filename
    const filename = args.filename ?? deriveFilename(args.url);
    const fnValidation = validateFilename(filename);
    if (!fnValidation.valid) {
      return formatError("download_from_url", new REMnuxError(
        fnValidation.error || "Invalid filename",
        "INVALID_FILENAME",
        "validation",
        "Use alphanumeric characters, hyphens, underscores, and dots only",
      ), startTime);
    }

    const filePath = `${config.samplesDir}/${filename}`;

    // Check if file exists (unless overwrite)
    if (!args.overwrite) {
      try {
        const checkResult = await connector.execute(["test", "-e", filePath], { timeout: 5000 });
        if (checkResult.exitCode === 0) {
          return formatError("download_from_url", new REMnuxError(
            `File already exists: ${filename}. Use overwrite=true to replace.`,
            "FILE_EXISTS",
            "validation",
            "Set overwrite=true or choose a different filename",
          ), startTime);
        }
      } catch {
        // test command failed — file doesn't exist, proceed
      }
    }

    // Ensure samples dir exists
    try {
      await connector.execute(["mkdir", "-p", config.samplesDir], { timeout: 5000 });
    } catch {
      // ignore — real errors surface below
    }

    if (method === "thug") {
      return await handleThugDownload(deps, args, headers, filename, filePath, startTime);
    }

    // ── Curl path ──────────────────────────────────────────────────────────
    const timeoutSecs = args.timeout ?? config.timeout;

    // Build curl command
    const headerFlags = headers.map(h => `-H '${h}'`).join(" ");
    const curlCmd = [
      "curl -sSfL",
      `--max-filesize ${MAX_FILESIZE}`,
      `--max-redirs ${MAX_REDIRS}`,
      `--max-time ${timeoutSecs}`,
      headerFlags,
      `-o '${filePath}'`,
      `'${args.url}'`,
    ].filter(Boolean).join(" ");

    const result = await connector.executeShell(curlCmd, {
      timeout: (timeoutSecs + 10) * 1000, // shell timeout slightly longer than curl timeout
      cwd: config.samplesDir,
    });

    if (result.exitCode !== 0) {
      // Clean up partial file left by curl
      try {
        await connector.execute(["rm", "-f", filePath], { timeout: 5000 });
      } catch { /* ignore cleanup errors */ }

      const curlError = CURL_ERRORS[result.exitCode] || `curl failed with exit code ${result.exitCode}`;
      const stderr = result.stderr?.trim() || "";
      return formatError("download_from_url", new REMnuxError(
        `Download failed: ${curlError}${stderr ? ` — ${stderr}` : ""}`,
        "DOWNLOAD_FAILED",
        "tool_failure",
        "Check that the URL is accessible and the server is responding",
      ), startTime);
    }

    // Gather file info (same pattern as get-file-info.ts)
    const info = await gatherFileInfo(connector, filePath, filename);

    return formatResponse("download_from_url", {
      method: "curl",
      url: args.url,
      ...info,
    }, startTime);

  } catch (error) {
    return formatError("download_from_url", toREMnuxError(error), startTime);
  }
}

/**
 * Handle download via thug honeyclient.
 */
async function handleThugDownload(
  deps: HandlerDeps,
  args: DownloadFromUrlArgs,
  headers: string[],
  filename: string,
  filePath: string,
  startTime: number,
) {
  const { connector, config } = deps;
  const timeoutSecs = args.timeout ?? DEFAULT_THUG_TIMEOUT;

  // Parse supported thug flags from headers
  let userAgent: string | undefined;
  let referer: string | undefined;
  const unsupportedHeaders: string[] = [];

  for (const h of headers) {
    const [name, ...rest] = h.split(":");
    const headerName = name.trim().toLowerCase();
    const headerValue = rest.join(":").trim();
    if (headerName === "user-agent") {
      userAgent = headerValue;
    } else if (headerName === "referer") {
      referer = headerValue;
    } else {
      unsupportedHeaders.push(name.trim());
    }
  }

  // Build thug command
  const thugOutputDir = `${config.outputDir}/thug-${Date.now()}`;
  const parts = ["thug"];
  if (userAgent) parts.push(`-u '${userAgent}'`);
  if (referer) parts.push(`-r '${referer}'`);
  parts.push(`-n '${thugOutputDir}'`);
  parts.push(`'${args.url}'`);
  const thugCmd = parts.join(" ");

  const result = await connector.executeShell(thugCmd, {
    timeout: (timeoutSecs + 30) * 1000,
    cwd: config.samplesDir,
  });

  // Thug may exit non-zero but still produce output; check for downloaded files
  // Find files in thug output (skip HTML and log files)
  const findCmd = `find '${thugOutputDir}' -type f ! -name '*.html' ! -name '*.log' ! -name 'analysis.json' 2>/dev/null | head -20`;
  let downloadedFiles: string[] = [];
  try {
    const findResult = await connector.executeShell(findCmd, { timeout: 15000 });
    if (findResult.stdout) {
      downloadedFiles = findResult.stdout.trim().split("\n").filter(Boolean);
    }
  } catch {
    // no files found
  }

  if (downloadedFiles.length === 0) {
    const stderr = result.stderr?.trim() || "";
    return formatError("download_from_url", new REMnuxError(
      `Thug did not download any files${stderr ? ` — ${stderr}` : ""}`,
      "DOWNLOAD_FAILED",
      "tool_failure",
      "The URL may not serve downloadable content, or thug encountered an error",
    ), startTime);
  }

  // Copy first file to samples dir (or use provided filename)
  const firstFile = downloadedFiles[0];
  const copyCmd = `cp '${firstFile}' '${filePath}'`;
  await connector.executeShell(copyCmd, { timeout: 10000 });

  // Gather file info
  const info = await gatherFileInfo(connector, filePath, filename);

  const warnings: string[] = [];
  if (unsupportedHeaders.length > 0) {
    warnings.push(`Thug does not support custom headers: ${unsupportedHeaders.join(", ")}. Only User-Agent and Referer are supported.`);
  }
  if (downloadedFiles.length > 1) {
    warnings.push(`Thug downloaded ${downloadedFiles.length} files. Only the first was copied to samples. Others available in: ${thugOutputDir}`);
  }

  return formatResponse("download_from_url", {
    method: "thug",
    url: args.url,
    thug_output_dir: thugOutputDir,
    thug_exit_code: result.exitCode,
    ...(warnings.length > 0 ? { warnings } : {}),
    ...info,
  }, startTime);
}

/**
 * Gather file metadata (type, hashes, size) — mirrors get-file-info pattern.
 */
async function gatherFileInfo(
  connector: HandlerDeps["connector"],
  filePath: string,
  filename: string,
): Promise<Record<string, unknown>> {
  let fileType = "";
  let sha256 = "";
  let md5 = "";
  let sha1 = "";
  let sizeBytes: number | null = null;

  try {
    const r = await connector.execute(["file", filePath], { timeout: 30000 });
    if (r.stdout) fileType = r.stdout.trim();
  } catch { /* skip */ }

  try {
    const r = await connector.execute(["sha256sum", filePath], { timeout: 30000 });
    if (r.stdout) sha256 = r.stdout.trim().split(/\s+/)[0] || "";
  } catch { /* skip */ }

  try {
    const r = await connector.execute(["md5sum", filePath], { timeout: 30000 });
    if (r.stdout) md5 = r.stdout.trim().split(/\s+/)[0] || "";
  } catch { /* skip */ }

  try {
    const r = await connector.execute(["sha1sum", filePath], { timeout: 30000 });
    if (r.stdout) sha1 = r.stdout.trim().split(/\s+/)[0] || "";
  } catch { /* skip */ }

  try {
    const r = await connector.execute(["stat", "-c", "%s", filePath], { timeout: 30000 });
    if (r.stdout && r.exitCode === 0) {
      sizeBytes = parseInt(r.stdout.trim(), 10);
    }
  } catch { /* skip */ }

  return {
    file: filename,
    file_type: fileType,
    sha256,
    sha1,
    md5,
    ...(sizeBytes !== null ? { size_bytes: sizeBytes } : {}),
  };
}
