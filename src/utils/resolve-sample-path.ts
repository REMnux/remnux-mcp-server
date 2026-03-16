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
  mode: string,
): { filePath: string; normalizedFile: string } {
  let normalizedFile = file;

  // In local mode, absolute paths bypass samplesDir
  if (mode === "local" && file.startsWith("/")) {
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
