import { basename } from "path";

/**
 * Normalize the user-supplied file parameter and resolve to a full path.
 *
 * Strips a leading directory component that matches the samplesDir basename
 * (e.g., "samples/foo.exe" -> "foo.exe") to prevent path duplication.
 */
export function resolveSamplePath(
  file: string,
  samplesDir: string,
  _mode: string,
): { filePath: string; normalizedFile: string } {
  let normalizedFile = file;

  // Absolute paths are resolved as-is on the target system — the host in local mode,
  // the container/VM in docker/ssh mode. They are never re-rooted under samplesDir,
  // which would otherwise duplicate the prefix (e.g. "/samples//home/.../sample") and
  // fail with a confusing "file not found". This matters for the extract -> analyze
  // chain, where extract_archive returns an absolute `extracted_to`. Sandbox mode, when
  // enabled, is enforced separately by validateFilePath() in each handler, so allowing
  // absolute paths here does not weaken the sandbox.
  if (file.startsWith("/")) {
    return { filePath: file, normalizedFile: file };
  }

  // Strip leading samplesDir basename to prevent duplication
  // e.g., "samples/sample.exe" -> "sample.exe" when samplesDir ends in /samples
  const base = basename(samplesDir);
  if (normalizedFile.startsWith(base + "/")) {
    normalizedFile = normalizedFile.slice(base.length + 1);
  }

  return {
    filePath: `${samplesDir}/${normalizedFile}`,
    normalizedFile,
  };
}
