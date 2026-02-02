/**
 * Archive extraction module for REMnux MCP server
 *
 * Supports .zip, .7z, and .rar archives with automatic password detection.
 * Passwords are tried from a configurable list for malware sample archives.
 */

import { readFileSync } from "fs";
import { dirname, join, basename, extname, resolve, normalize } from "path";
import { fileURLToPath } from "url";
import type { Connector, ExecResult } from "./connectors/index.js";

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

export type ArchiveType = "zip" | "7z" | "rar" | null;

export interface ExtractionResult {
  success: boolean;
  files: string[];
  password?: string;
  error?: string;
  outputDir: string;
}

/**
 * Detect archive type from filename extension
 */
export function detectArchiveType(filename: string): ArchiveType {
  const ext = extname(filename).toLowerCase();
  switch (ext) {
    case ".zip":
      return "zip";
    case ".7z":
      return "7z";
    case ".rar":
      return "rar";
    default:
      return null;
  }
}

/**
 * Load password list from config file
 * Returns default list if file not found
 */
export function loadPasswordList(): string[] {
  const defaultPasswords = ["infected", "malware", "virus"];

  try {
    const passwordFile = join(__dirname, "config", "archive-passwords.txt");
    const content = readFileSync(passwordFile, "utf-8");
    const passwords = content
      .split("\n")
      .map((line) => line.trim())
      .filter((line) => line.length > 0 && !line.startsWith("#"));

    return passwords.length > 0 ? passwords : defaultPasswords;
  } catch {
    // Fallback to defaults if file not found
    return defaultPasswords;
  }
}

/**
 * Build extraction command for given archive type and tool
 *
 * @param archiveType - Type of archive (zip, 7z, rar)
 * @param archivePath - Full path to archive file
 * @param outputDir - Directory to extract files to
 * @param password - Optional password for encrypted archives
 * @returns Command array for execution
 */
export function getExtractionCommand(
  archiveType: ArchiveType,
  archivePath: string,
  outputDir: string,
  password?: string
): string[] {
  // Validate inputs don't contain shell metacharacters
  // This is defense-in-depth; the connector should also escape properly
  if (password && /[;&|`$\n\r'"\\]/.test(password)) {
    throw new Error("Password contains invalid characters");
  }

  switch (archiveType) {
    case "7z":
      // 7z x archive.7z -ooutputdir -ppassword -y
      // -y: assume yes on all queries (non-interactive)
      const cmd7z = ["7z", "x", archivePath, `-o${outputDir}`, "-y"];
      if (password) {
        cmd7z.push(`-p${password}`);
      }
      return cmd7z;

    case "zip":
      // unzip -P password -d outputdir archive.zip
      // -o: overwrite without prompting
      const cmdZip = ["unzip", "-o"];
      if (password) {
        cmdZip.push("-P", password);
      }
      cmdZip.push("-d", outputDir, archivePath);
      return cmdZip;

    case "rar":
      // unrar x -ppassword archive.rar outputdir/
      // -o+: overwrite existing files
      const cmdRar = ["unrar", "x", "-o+"];
      if (password) {
        cmdRar.push(`-p${password}`);
      }
      cmdRar.push(archivePath, outputDir + "/");
      return cmdRar;

    default:
      throw new Error(`Unsupported archive type: ${archiveType}`);
  }
}

/**
 * Check if extraction result indicates wrong password
 */
function isWrongPasswordError(result: ExecResult, _archiveType: ArchiveType): boolean {
  const output = (result.stderr + result.stdout).toLowerCase();

  // Common password error patterns across tools
  const passwordErrors = [
    "wrong password",
    "incorrect password",
    "bad password",
    "password required",
    "encrypted",
    "need password",
    "checksum error", // 7z uses this for wrong password
    "crc failed", // unrar uses this for wrong password
  ];

  // Check if exit code indicates failure AND output mentions password issues
  if (result.exitCode !== 0) {
    return passwordErrors.some((pattern) => output.includes(pattern));
  }

  return false;
}

/**
 * List files in a directory
 */
async function listExtractedFiles(
  connector: Connector,
  outputDir: string
): Promise<string[]> {
  try {
    const result = await connector.execute(
      ["find", outputDir, "-type", "f", "-printf", "%P\\n"],
      { timeout: 30000 }
    );

    if (result.exitCode === 0 && result.stdout) {
      return result.stdout
        .split("\n")
        .map((f) => f.trim())
        .filter((f) => f.length > 0);
    }

    // Fallback to ls if find doesn't support -printf (e.g., BSD)
    const lsResult = await connector.execute(
      ["ls", "-1R", outputDir],
      { timeout: 30000 }
    );

    if (lsResult.exitCode === 0 && lsResult.stdout) {
      return lsResult.stdout
        .split("\n")
        .map((f) => f.trim())
        .filter((f) => f.length > 0 && !f.endsWith(":"));
    }

    return [];
  } catch {
    return [];
  }
}

/**
 * Validate that extracted files don't escape the sandbox (zip-slip protection)
 * Malicious archives can contain entries like "../../../etc/cron.d/evil"
 *
 * @param files - Relative file paths from extraction
 * @param outputDir - Expected output directory
 * @returns Array of files that attempted path escape (empty if all safe)
 */
function validateExtractedPaths(files: string[], outputDir: string): string[] {
  const escapeAttempts: string[] = [];
  const normalizedBase = resolve(outputDir);

  for (const file of files) {
    // Check for obvious traversal patterns
    if (file.includes("..") || file.startsWith("/")) {
      escapeAttempts.push(file);
      continue;
    }

    // Resolve the full path and ensure it stays within outputDir
    const resolvedPath = resolve(outputDir, normalize(file));
    if (!resolvedPath.startsWith(normalizedBase + "/") && resolvedPath !== normalizedBase) {
      escapeAttempts.push(file);
    }
  }

  return escapeAttempts;
}

/**
 * Extract an archive file with automatic password detection
 *
 * @param connector - Connector to execute commands on REMnux
 * @param archivePath - Full path to archive file inside REMnux
 * @param samplesDir - Base samples directory for output
 * @param customPassword - Optional password to try first
 * @param outputSubdir - Optional subdirectory name (defaults to archive name without extension)
 * @returns Extraction result with file list and password used
 */
export async function extractArchive(
  connector: Connector,
  archivePath: string,
  samplesDir: string,
  customPassword?: string,
  outputSubdir?: string
): Promise<ExtractionResult> {
  // Detect archive type
  const archiveType = detectArchiveType(archivePath);
  if (!archiveType) {
    return {
      success: false,
      files: [],
      error: `Unsupported archive format: ${extname(archivePath)}`,
      outputDir: "",
    };
  }

  // Determine output directory
  const archiveName = basename(archivePath, extname(archivePath));
  const subdir = outputSubdir || archiveName;
  const outputDir = join(samplesDir, subdir);

  // Create output directory
  const mkdirResult = await connector.execute(["mkdir", "-p", outputDir], {
    timeout: 10000,
  });
  if (mkdirResult.exitCode !== 0) {
    return {
      success: false,
      files: [],
      error: `Failed to create output directory: ${mkdirResult.stderr}`,
      outputDir,
    };
  }

  // Build password list to try
  const passwordsToTry: (string | undefined)[] = [];

  // 1. Custom password first if provided
  if (customPassword) {
    passwordsToTry.push(customPassword);
  }

  // 2. Try without password (archive might not be encrypted)
  passwordsToTry.push(undefined);

  // 3. Add passwords from config file
  const configPasswords = loadPasswordList();
  for (const pwd of configPasswords) {
    if (pwd !== customPassword) {
      // Avoid duplicates
      passwordsToTry.push(pwd);
    }
  }

  // Try extraction with each password
  let lastError = "";
  for (const password of passwordsToTry) {
    try {
      const cmd = getExtractionCommand(archiveType, archivePath, outputDir, password);
      const result = await connector.execute(cmd, { timeout: 120000 });

      if (result.exitCode === 0) {
        // Success! List extracted files
        const files = await listExtractedFiles(connector, outputDir);

        // Validate for zip-slip attacks (path traversal in archive entries)
        const escapeAttempts = validateExtractedPaths(files, outputDir);
        if (escapeAttempts.length > 0) {
          // Clean up potentially malicious files
          await connector.execute(["rm", "-rf", outputDir], { timeout: 30000 });
          return {
            success: false,
            files: [],
            error: `Archive contains path escape attempts (zip-slip): ${escapeAttempts.slice(0, 3).join(", ")}${escapeAttempts.length > 3 ? ` and ${escapeAttempts.length - 3} more` : ""}`,
            outputDir,
          };
        }

        return {
          success: true,
          files,
          password: password, // undefined if no password was needed
          outputDir,
        };
      }

      // Check if this is a password error
      if (isWrongPasswordError(result, archiveType)) {
        lastError = "Incorrect password";
        continue; // Try next password
      }

      // Some other error - might still try other passwords for encrypted archives
      lastError = result.stderr || result.stdout || "Unknown extraction error";
    } catch (err) {
      lastError = err instanceof Error ? err.message : "Extraction failed";
    }
  }

  // All passwords failed
  return {
    success: false,
    files: [],
    error: `Extraction failed: ${lastError}. Tried ${passwordsToTry.length} password(s).`,
    outputDir,
  };
}
