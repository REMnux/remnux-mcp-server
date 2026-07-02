import type { HandlerDeps } from "./types.js";
import type { ExtractArchiveArgs } from "../schemas/tools.js";
import { validateFilePath } from "../security/blocklist.js";
import { extractArchive, detectArchiveType, describeMultiVolumePart } from "../archive-extractor.js";
import { formatResponse, formatError } from "../response.js";
import { REMnuxError } from "../errors/remnux-error.js";
import { toREMnuxError } from "../errors/error-mapper.js";

export async function handleExtractArchive(
  deps: HandlerDeps,
  args: ExtractArchiveArgs
) {
  const startTime = Date.now();
  const { connector, config } = deps;

  // Validate archive file path (skip unless --sandbox)
  if (!config.noSandbox) {
    const validation = validateFilePath(args.archive_file, config.samplesDir);
    if (!validation.safe) {
      return formatError("extract_archive", new REMnuxError(
        validation.error || "Invalid archive file path",
        "INVALID_PATH",
        "validation",
        "Use a relative path within the samples directory",
      ), startTime);
    }
  }

  // Security: Validate output subdirectory if provided
  if (args.output_subdir && !config.noSandbox) {
    if (args.output_subdir.trim() === "") {
      return formatError("extract_archive", new REMnuxError(
        "output_subdir cannot be blank",
        "INVALID_SUBDIR",
        "validation",
        "Provide a non-empty subdirectory name without special characters",
      ), startTime);
    }
    if (args.output_subdir.includes("..") || args.output_subdir.includes("/") || args.output_subdir.includes("\\")) {
      return formatError("extract_archive", new REMnuxError(
        "Invalid output subdirectory name",
        "INVALID_SUBDIR",
        "validation",
        "Subdirectory must not contain path separators or '..'",
      ), startTime);
    }
    if (/[;&|`$\n\r'"\\]/.test(args.output_subdir)) {
      return formatError("extract_archive", new REMnuxError(
        "Output subdirectory contains invalid characters",
        "INVALID_SUBDIR",
        "validation",
        "Use only alphanumeric characters, hyphens, and underscores",
      ), startTime);
    }
  }

  // Security: validate the password up front (argument/option injection guard).
  // This is not a path-sandbox aid, so it applies even with --no-sandbox: a
  // leading "-" would be parsed by unzip as an option (["-P", password]), and
  // shell metacharacters are rejected as defense-in-depth. Surfacing the error
  // here gives a clear message instead of it being swallowed by the password
  // retry loop in extractArchive (getExtractionCommand enforces the same rules).
  if (args.password) {
    if (args.password.startsWith("-")) {
      return formatError("extract_archive", new REMnuxError(
        "Password cannot start with '-' (option injection)",
        "INVALID_PASSWORD",
        "validation",
        "Provide a password that does not begin with a hyphen",
      ), startTime);
    }
    if (/[;&|`$\n\r'"\\]/.test(args.password)) {
      return formatError("extract_archive", new REMnuxError(
        "Password contains invalid characters",
        "INVALID_PASSWORD",
        "validation",
        "Remove shell metacharacters from the password",
      ), startTime);
    }
  }

  // Multi-volume trailing part: point the agent at the first volume instead of
  // failing later with a misleading wrong-password/corrupt error.
  const multiVolume = describeMultiVolumePart(args.archive_file);
  if (multiVolume) {
    return formatError("extract_archive", new REMnuxError(
      "Archive is a trailing volume of a multi-volume set",
      "MULTI_VOLUME_PART",
      "validation",
      multiVolume,
    ), startTime);
  }

  // Verify archive type is supported
  const archiveType = detectArchiveType(args.archive_file);
  if (!archiveType) {
    return formatError("extract_archive", new REMnuxError(
      "Unsupported archive format. Supported: .zip, .7z, .rar",
      "UNSUPPORTED_FORMAT",
      "validation",
      "Rename the file with a supported extension or use a different tool",
    ), startTime);
  }

  // Build full archive path
  const archivePath = `${config.samplesDir}/${args.archive_file}`;

  try {
    const result = await extractArchive(
      connector,
      archivePath,
      config.samplesDir,
      args.password,
      args.output_subdir
    );

    if (result.success) {
      // Store archive metadata for download_file to reuse
      if (result.password && archiveType) {
        deps.sessionState.storeArchiveInfo(
          args.archive_file,
          result.files,
          archiveType,
          result.password
        );
      }

      return formatResponse("extract_archive", {
        extracted_to: result.outputDir,
        files: result.files,
        file_count: result.files.length,
        password_used: result.password || "(none - archive was not encrypted)",
      }, startTime);
    } else {
      // Give a password-specific, actionable suggestion when the failure was a
      // wrong/absent password, rather than the generic "corrupted archive" hint.
      // Match the specific "Incorrect password" reason, not any mention of
      // "password" — the composed error always ends with "Tried N password(s)".
      const isPasswordFailure = /incorrect password/i.test(result.error || "");
      const suggestion = isPasswordFailure
        ? "Most likely the archive is password-protected with a password not in the auto-detect list (infected, malware, virus). " +
          "If you know the password — it is often in the email or context that delivered the sample — pass it as the 'password' argument. " +
          "WinZip AES-256 .zip and header-encrypted .7z are supported, so a supported format is not the issue. " +
          "If you are confident the password is correct, the archive may instead be corrupt, truncated (an incomplete download), or a multi-volume set with parts missing — check the file size and that any sibling volumes are present."
        : "Check that the archive is valid and not corrupted";
      return formatError("extract_archive", new REMnuxError(
        result.error || "Extraction failed",
        "EXTRACTION_FAILED",
        "tool_failure",
        suggestion,
      ), startTime);
    }
  } catch (error) {
    return formatError("extract_archive", toREMnuxError(error, deps.config.mode), startTime);
  }
}
