import type { HandlerDeps } from "./types.js";
import type { GetFileInfoArgs } from "../schemas/tools.js";
import { validateFilePath } from "../security/blocklist.js";
import { formatResponse, formatError } from "../response.js";
import { REMnuxError } from "../errors/remnux-error.js";
import { toREMnuxError } from "../errors/error-mapper.js";

export async function handleGetFileInfo(
  deps: HandlerDeps,
  args: GetFileInfoArgs
) {
  const startTime = Date.now();
  try {
  const { connector, config } = deps;

  // Validate file path (skip unless --sandbox)
  if (!config.noSandbox) {
    const validation = validateFilePath(args.file, config.samplesDir);
    if (!validation.safe) {
      return formatError("get_file_info", new REMnuxError(
        validation.error || "Invalid file path",
        "INVALID_PATH",
        "validation",
        "Use a relative path within the samples directory",
      ), startTime);
    }
  }

  const filePath = (config.mode === "local" && args.file.startsWith("/")) ? args.file : `${config.samplesDir}/${args.file}`;
  let fileType = "";
  let sha256 = "";
  let md5 = "";
  let sizeBytes: number | null = null;

  // file command
  try {
    const result = await connector.execute(["file", filePath], { timeout: 30000 });
    if (result.stdout) fileType = result.stdout.trim();
  } catch (error) {
    const mapped = toREMnuxError(error, config.mode);
    if (mapped.code === "CONNECTION_FAILED") {
      return formatError("get_file_info", mapped, startTime);
    }
    // Non-connection errors: continue (file command failure is non-fatal)
  }

  // sha256sum
  try {
    const result = await connector.execute(["sha256sum", filePath], { timeout: 30000 });
    if (result.stdout) sha256 = result.stdout.trim().split(/\s+/)[0] || "";
  } catch { /* skip */ }

  // md5sum
  try {
    const result = await connector.execute(["md5sum", filePath], { timeout: 30000 });
    if (result.stdout) md5 = result.stdout.trim().split(/\s+/)[0] || "";
  } catch { /* skip */ }

  // sha1sum
  let sha1 = "";
  try {
    const result = await connector.execute(["sha1sum", filePath], { timeout: 30000 });
    if (result.stdout) sha1 = result.stdout.trim().split(/\s+/)[0] || "";
  } catch { /* skip */ }

  // file size (stat -c works on Linux/REMnux; wc -c as fallback)
  try {
    const result = await connector.execute(["stat", "-c", "%s", filePath], { timeout: 30000 });
    if (result.stdout && result.exitCode === 0) {
      sizeBytes = parseInt(result.stdout.trim(), 10);
    }
  } catch { /* skip */ }
  if (sizeBytes === null) {
    try {
      const result = await connector.execute(["wc", "-c", filePath], { timeout: 30000 });
      if (result.stdout && result.exitCode === 0) {
        sizeBytes = parseInt(result.stdout.trim().split(/\s+/)[0] || "0", 10);
      }
    } catch { /* skip */ }
  }

  if (!fileType && !sha256 && !md5) {
    return formatError("get_file_info", new REMnuxError(
      "Could not get file info",
      "EMPTY_OUTPUT",
      "tool_failure",
      "Check that the file exists and is readable",
    ), startTime);
  }

  return formatResponse("get_file_info", {
    file: args.file,
    file_type: fileType,
    sha256,
    sha1,
    md5,
    ...(sizeBytes !== null ? { size_bytes: sizeBytes } : {}),
  }, startTime);
  } catch (error) {
    return formatError("get_file_info", toREMnuxError(error, deps.config.mode), startTime);
  }
}
