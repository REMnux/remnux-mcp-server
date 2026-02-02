import type { HandlerDeps } from "./types.js";
import type { UploadFromHostArgs } from "../schemas/tools.js";
import { uploadSampleFromHost, validateHostPath, validateFilename } from "../file-upload.js";
import { formatResponse, formatError } from "../response.js";
import { REMnuxError } from "../errors/remnux-error.js";
import { toREMnuxError } from "../errors/error-mapper.js";
import { basename } from "path";

export async function handleUploadFile(
  deps: HandlerDeps,
  args: UploadFromHostArgs
) {
  const startTime = Date.now();
  const { connector, config } = deps;

  // Validate host path first
  const pathValidation = validateHostPath(args.host_path);
  if (!pathValidation.valid) {
    return formatError("upload_file", new REMnuxError(
      pathValidation.error || "Invalid host path",
      "INVALID_PATH",
      "validation",
      "Provide an absolute path to a file on the host filesystem",
    ), startTime);
  }

  // Validate filename if provided
  const targetFilename = args.filename ?? basename(args.host_path);
  const filenameValidation = validateFilename(targetFilename);
  if (!filenameValidation.valid) {
    return formatError("upload_file", new REMnuxError(
      filenameValidation.error || "Invalid filename",
      "INVALID_FILENAME",
      "validation",
      "Use alphanumeric characters, hyphens, underscores, and dots only",
    ), startTime);
  }

  try {
    const result = await uploadSampleFromHost(
      connector,
      config.samplesDir,
      args.host_path,
      args.filename,
      args.overwrite
    );

    if (result.success) {
      return formatResponse("upload_file", result as unknown as Record<string, unknown>, startTime);
    } else {
      return formatError("upload_file", new REMnuxError(
        result.error || "Upload failed",
        "UPLOAD_FAILED",
        "tool_failure",
        "Check that the file exists and is readable on the host filesystem",
      ), startTime);
    }
  } catch (error) {
    return formatError("upload_file", toREMnuxError(error), startTime);
  }
}
