import type { HandlerDeps } from "./types.js";
import type { ExtractArchiveArgs } from "../schemas/tools.js";
import { validateFilePath } from "../security/blocklist.js";
import { extractArchive, detectArchiveType } from "../archive-extractor.js";
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
      return formatError("extract_archive", new REMnuxError(
        result.error || "Extraction failed",
        "EXTRACTION_FAILED",
        "tool_failure",
        "Check that the archive is valid and not corrupted",
      ), startTime);
    }
  } catch (error) {
    return formatError("extract_archive", toREMnuxError(error), startTime);
  }
}
