import { existsSync, lstatSync, statSync } from "fs";
import { join, basename } from "path";
import type { HandlerDeps } from "./types.js";
import type { DownloadFileArgs } from "../schemas/tools.js";
import { validateFilePath } from "../security/blocklist.js";
import { validateHostPath, confineHostPath } from "../file-upload.js";
import { formatResponse, formatError } from "../response.js";
import { REMnuxError } from "../errors/remnux-error.js";
import { toREMnuxError } from "../errors/error-mapper.js";
import { DEFAULT_ARCHIVE_PASSWORD, DEFAULT_ARCHIVE_FORMAT } from "../state/session.js";
import { isCommandAbsent } from "../utils/missing-command.js";

// Raw transfer is a choice for harmless files only. Never steer a sample there.
const ARCHIVE_REMEDY =
  "If the file is a sample, keep it archived and retry after resolving the error. " +
  "Pass archive: false only for harmless files such as text reports";

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

/**
 * Check the host-side destination before the transfer writes it. This is the
 * one place where download_file touches the machine the server runs on, which
 * in docker/ssh mode is the analyst's workstation, outside the container/VM
 * isolation boundary.
 *
 * - A symlink at the destination is always refused: docker cp and the SFTP
 *   write stream both follow it, so a link planted earlier (for example by a
 *   previous download of a container-side symlink) would redirect the write
 *   to wherever it points.
 * - Any other existing entry is refused unless the caller passed
 *   overwrite: true, so a transfer never replaces a host file by accident.
 *
 * Preflight only: the transfer itself is docker cp or SFTP, so the check and
 * the write are not atomic (the same accepted race the README notes for
 * path validation).
 */
export function checkHostDestination(
  hostPath: string,
  overwrite: boolean,
): { ok: true } | { ok: false; error: REMnuxError } {
  let existing: ReturnType<typeof lstatSync> | undefined;
  try {
    existing = lstatSync(hostPath);
  } catch {
    return { ok: true }; // nothing there: the normal case
  }
  if (existing.isSymbolicLink()) {
    return {
      ok: false,
      error: new REMnuxError(
        `Destination is a symlink and the transfer would write through it: ${hostPath}`,
        "INVALID_PATH",
        "validation",
        "Remove the symlink or choose a different output_path",
      ),
    };
  }
  if (!overwrite) {
    return {
      ok: false,
      error: new REMnuxError(
        `Destination already exists on the host: ${hostPath}`,
        "FILE_EXISTS",
        "validation",
        "Pass overwrite: true to replace it, or choose a different output_path",
      ),
    };
  }
  return { ok: true };
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

  // Opt-in confinement (--sandbox): the destination directory must resolve inside
  // the same ingest root that confines upload_from_host's source, so both ends of
  // host-side file transfer answer to one flag. Defaults to samplesDir; docker/ssh
  // deployments set --ingest-root to a host-side dir (enforced at startup).
  if (!config.noSandbox) {
    const confinement = confineHostPath(args.output_path, config.ingestRoot ?? config.samplesDir);
    if (!confinement.valid) {
      return formatError("download_file", new REMnuxError(
        confinement.error!.replace("host_path", "output_path"),
        "INVALID_PATH",
        "validation",
        "With --sandbox, output_path must be a directory inside --ingest-root",
      ), startTime);
    }
  }

  const overwrite = args.overwrite === true;
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
      let archiveFormat = archiveMeta?.format ?? DEFAULT_ARCHIVE_FORMAT;
      const archivePassword = archiveMeta?.password ?? DEFAULT_ARCHIVE_PASSWORD;

      // Defense-in-depth: reject passwords with shell metacharacters
      if (/[;&|`$\n\r'"\\]/.test(archivePassword)) {
        return formatError("download_file", new REMnuxError(
          "Archive password contains unsafe characters",
          "INVALID_PASSWORD",
          "validation",
          ARCHIVE_REMEDY,
        ), startTime);
      }

      // A file extracted from a .rar is re-archived as .rar, but rar is not on every
      // REMnux system (stock arm64 REMnux omits it). When the target positively
      // reports it missing, use 7z with encrypted file names and the same password.
      // With an unknown probe result the code keeps rar, so a failure stays visible.
      let formatNote: string | undefined;
      if (archiveFormat === "rar" && await isCommandAbsent(connector, "rar")) {
        archiveFormat = "7z";
        formatNote =
          "rar is not installed on this REMnux system, so the file was archived as 7z " +
          "with the same password and encrypted file names.";
      }

      // Create temp archive path inside REMnux
      const timestamp = Date.now();
      const archiveName = `${filename}${archiveExtension(archiveFormat)}`;
      const remoteTmpArchive = `/tmp/dl_${timestamp}_${archiveName}`;

      // Check the host destination before creating the archive inside REMnux.
      const destination = checkHostDestination(join(args.output_path, archiveName), overwrite);
      if (!destination.ok) {
        return formatError("download_file", destination.error, startTime);
      }

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
          ARCHIVE_REMEDY,
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
        ...(formatNote && { note: formatNote }),
      }, startTime);
    }

    // No archiving — transfer raw file
    const hostPath = join(args.output_path, filename);
    const destination = checkHostDestination(hostPath, overwrite);
    if (!destination.ok) {
      return formatError("download_file", destination.error, startTime);
    }
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
