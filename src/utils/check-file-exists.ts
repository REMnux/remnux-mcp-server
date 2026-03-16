import type { Connector } from "../connectors/index.js";
import { REMnuxError } from "../errors/remnux-error.js";

/**
 * Check that a file exists on the target system (works across all connector modes).
 * Returns a REMnuxError if the file is missing, or null if it exists.
 */
export async function checkFileExists(
  connector: Connector,
  filePath: string,
): Promise<REMnuxError | null> {
  try {
    const result = await connector.execute(["test", "-f", filePath], { timeout: 5000 });
    if (result.exitCode !== 0) {
      return new REMnuxError(
        `File not found: ${filePath}`,
        "FILE_NOT_FOUND",
        "not_found",
        "Check the filename with list_files, or upload the file first with upload_from_host",
      );
    }
  } catch {
    return new REMnuxError(
      `Could not verify file exists: ${filePath}`,
      "FILE_NOT_FOUND",
      "not_found",
      "Check the filename with list_files, or upload the file first with upload_from_host",
    );
  }
  return null;
}
