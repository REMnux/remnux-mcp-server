import { existsSync, statSync } from "fs";
import { join, basename } from "path";
import type { HandlerDeps } from "./types.js";
import type { DownloadFileArgs } from "../schemas/tools.js";
import { validateFilePath } from "../security/blocklist.js";
import { validateHostPath } from "../file-upload.js";
import { formatResponse, formatError } from "../response.js";
import { REMnuxError } from "../errors/remnux-error.js";
import { toREMnuxError } from "../errors/error-mapper.js";
import { DEFAULT_ARCHIVE_PASSWORD, DEFAULT_ARCHIVE_FORMAT } from "../state/session.js";

const MAX_DOWNLOAD_SIZE = 200 * 1024 * 1024; // 200MB

/**
 * Build the command to create a password-protected archive inside REMnux.
 */
function getArchiveCommand(
  format: "zip" | "7z" | "rar",
  archivePath: string,
  sourcePath: string,
  password: string
): string[] {
  switch (format) {
    case "zip":
      return ["zip", "-j", "-P", password, archivePath, sourcePath];
    case "7z":
      return ["7z", "a", `-p${password}`, "-mhe=on", archivePath, sourcePath];
    case "rar":
      return ["rar", "a", `-p${password}`, "-hp", archivePath, sourcePath];
  }
}

function archiveExtension(format: "zip" | "7z" | "rar"): string {
  return `.${format}`;
}

export async function handleDownloadFile(
  deps: HandlerDeps,
  args: DownloadFileArgs
) {
  const startTime = Date.now();
  const { connector, config } = deps;
  const shouldArchive = args.archive !== false;

  // Validate file path (skip unless --sandbox)
  if (!config.noSandbox) {
    const validation = validateFilePath(args.file_path, config.outputDir);
    if (!validation.safe) {
      return formatError("download_file", new REMnuxError(
        validation.error || "Invalid file path",
        "INVALID_PATH",
        "validation",
        "Use a relative path within the output directory",
      ), startTime);
    }
  }

  // Validate outputPath
  const pathValidation = validateHostPath(args.output_path);
  if (!pathValidation.valid) {
    return formatError("download_file", new REMnuxError(
      pathValidation.error || "Invalid output path",
      "INVALID_PATH",
      "validation",
      "Provide an absolute path to a directory on the host filesystem",
    ), startTime);
  }

  // Verify output directory exists and is a directory
  if (!existsSync(args.output_path) || !statSync(args.output_path).isDirectory()) {
    return formatError("download_file", new REMnuxError(
      `Output path does not exist or is not a directory: ${args.output_path}`,
      "INVALID_PATH",
      "validation",
      "Provide an absolute path to an existing directory",
    ), startTime);
  }

  const fullPath = `${config.outputDir}/${args.file_path}`;

  try {
    // Get file size and hash (separate calls to avoid shell interpolation)
    const statResult = await connector.execute(
      ["stat", "-c", "%s", fullPath],
      { timeout: 30000 }
    );
    const hashResult = await connector.execute(
      ["sha256sum", fullPath],
      { timeout: 30000 }
    );

    const sizeBytes = parseInt((statResult.stdout || "0").trim(), 10);

    // Guard against oversized downloads
    if (sizeBytes > MAX_DOWNLOAD_SIZE) {
      return formatError("download_file", new REMnuxError(
        `File exceeds ${MAX_DOWNLOAD_SIZE / 1024 / 1024}MB download limit (got ${(sizeBytes / 1024 / 1024).toFixed(2)}MB)`,
        "FILE_TOO_LARGE",
        "validation",
        "Use run_tool with 'split' to break the file into smaller parts first",
      ), startTime);
    }

    const sha256 = (hashResult.stdout || "").trim().split(/\s+/)[0] || "unknown";
    const filename = basename(args.file_path);

    if (shouldArchive) {
      // Determine archive format and password from session state
      const archiveMeta = deps.sessionState.getArchiveInfo(filename);
      const archiveFormat = archiveMeta?.format ?? DEFAULT_ARCHIVE_FORMAT;
      const archivePassword = archiveMeta?.password ?? DEFAULT_ARCHIVE_PASSWORD;

      // Defense-in-depth: reject passwords with shell metacharacters
      if (/[;&|`$\n\r'"\\]/.test(archivePassword)) {
        return formatError("download_file", new REMnuxError(
          "Archive password contains unsafe characters",
          "INVALID_PASSWORD",
          "validation",
          "Try downloading with archive: false",
        ), startTime);
      }

      // Create temp archive path inside REMnux
      const timestamp = Date.now();
      const archiveName = `${filename}${archiveExtension(archiveFormat)}`;
      const remoteTmpArchive = `/tmp/dl_${timestamp}_${archiveName}`;

      // Create password-protected archive
      const archiveCmd = getArchiveCommand(archiveFormat, remoteTmpArchive, fullPath, archivePassword);
      const archiveResult = await connector.execute(archiveCmd, {
        timeout: Math.max(60000, sizeBytes / 1024),
      });

      if (archiveResult.exitCode !== 0) {
        return formatError("download_file", new REMnuxError(
          `Failed to create archive: ${archiveResult.stderr || archiveResult.stdout}`,
          "ARCHIVE_FAILED",
          "tool_failure",
          "Try downloading with archive: false",
        ), startTime);
      }

      // Transfer archive to host
      const hostPath = join(args.output_path, archiveName);
      try {
        await connector.readFileToPath(remoteTmpArchive, hostPath);
      } finally {
        // Clean up temp archive inside REMnux
        await connector.execute(["rm", "-f", remoteTmpArchive], { timeout: 10000 }).catch(() => {});
      }

      return formatResponse("download_file", {
        file_path: args.file_path,
        size_bytes: sizeBytes,
        sha256,
        host_path: hostPath,
        archived: true,
        archive_format: archiveFormat,
        archive_password: archivePassword,
      }, startTime);
    }

    // No archiving — transfer raw file
    const hostPath = join(args.output_path, filename);
    await connector.readFileToPath(fullPath, hostPath);

    return formatResponse("download_file", {
      file_path: args.file_path,
      size_bytes: sizeBytes,
      sha256,
      host_path: hostPath,
      archived: false,
    }, startTime);
  } catch (error) {
    return formatError("download_file", toREMnuxError(error, deps.config.mode), startTime);
  }
}
