/**
 * Security configuration for REMnux MCP server
 *
 * Threat model: All three modes (docker, ssh, local) execute commands inside a
 * disposable REMnux VM or container. Container/VM isolation is the security
 * boundary — not this module.
 *
 * This module prevents:
 * 1. Shell injection — malware output containing prompt injection could trick
 *    the AI into executing arbitrary code via eval, $(), backticks, etc.
 * 2. Dangerous pipes — pipes to interpreters (| bash, | python) blocked.
 *
 * Path sandboxing (isPathSafe, validateFilePath) is available as an opt-in
 * workflow aid via --sandbox, not as a security control.
 */

import { normalize, isAbsolute, resolve } from "path";
import { lstatSync, existsSync } from "fs";

/**
 * Blocked command patterns
 * Commands matching these patterns will be rejected regardless of tool
 */
export interface BlockedPattern {
  pattern: RegExp;
  category: string;
}

export const BLOCKED_PATTERNS: BlockedPattern[] = [
  // Null byte injection - truncates paths in C-based functions
  // Newlines allowed: enables multi-line scripts; container isolation is security boundary
  { pattern: /\x00/, category: "null byte injection" },

  // Shell escape / code execution — prevents prompt injection from triggering arbitrary code
  { pattern: /\beval\b/i, category: "shell escape" },
  { pattern: /(?<!-)\bexec\b/i, category: "shell escape" },
  { pattern: /`[^`]+`/, category: "shell escape (backtick)" },
  { pattern: /\$\([^)]+\)/, category: "shell escape (command substitution)" },
  { pattern: /\$\{[^}]+\}/, category: "shell escape (variable expansion)" },
  // Note: Simple $var (like $f in for-loops) is intentionally NOT blocked
  // The threat is command substitution ($(), ${}), not variable reference
  { pattern: /\$[0-9?$!@#]/, category: "shell escape (special variable)" },

  // Process substitution
  { pattern: /[<>]\s*\(/, category: "process substitution" },

  // Shell sourcing
  { pattern: /\bsource\b/i, category: "shell escape" },

  // Catastrophic command guard — prevents AI from accidentally destroying the analysis session
  // Only blocks root-level wipes (rm -rf /), not targeted deletes (rm -rf subdir/)
  { pattern: /rm\s+-[rR].*\s\/\s*$/, category: "catastrophic command (root wipe)" },
  { pattern: /rm\s+-[rR].*\s\/\*/, category: "catastrophic command (root wipe)" },
  { pattern: /\bmkfs\b/, category: "catastrophic command (format filesystem)" },
];

/**
 * Validate that a path is safe (within allowed directories)
 * @param path - The path to validate (relative to baseDir)
 * @param baseDir - The base directory that the path should be contained within
 * @returns true if the path is safe, false otherwise
 */
export function isPathSafe(path: string, baseDir: string): boolean {
  // Reject empty string (resolves to baseDir itself)
  if (path === "") return false;

  // Reject null bytes (can truncate paths in C-based functions)
  if (path.includes("\0")) return false;

  // Reject absolute paths
  if (isAbsolute(path)) return false;

  // Reject path traversal (check before normalization)
  if (path.includes("..")) return false;

  // Reject special characters that might cause shell issues
  if (/[;&|`$\n\r'"]/.test(path)) return false;

  // Reject home directory references
  if (path.startsWith("~")) return false;

  // Normalize the path to handle unicode normalization attacks
  const normalizedPath = normalize(path);

  // After normalization, check again for traversal (handles cases like "foo/../..")
  if (normalizedPath.includes("..") || normalizedPath.startsWith("..")) return false;

  // Verify the resolved path stays within baseDir
  const resolvedPath = resolve(baseDir, normalizedPath);
  const normalizedBase = resolve(baseDir);

  // The resolved path must start with the base directory
  if (!resolvedPath.startsWith(normalizedBase + "/") && resolvedPath !== normalizedBase) {
    return false;
  }

  return true;
}

/**
 * Check if a path is a symlink
 *
 * @param filePath - The full path to check (already resolved)
 * @returns true if the path is a symlink, false otherwise
 * @throws Error if the path doesn't exist
 */
export function isSymlink(filePath: string): boolean {
  if (!existsSync(filePath)) {
    throw new Error(`Path does not exist: ${filePath}`);
  }

  const stats = lstatSync(filePath);
  return stats.isSymbolicLink();
}

/**
 * Validate a file path for safe execution
 * Checks path safety (no traversal, no special chars, stays within baseDir)
 *
 * @param relativePath - Relative path from baseDir
 * @param baseDir - Base directory
 * @returns { safe: boolean, error?: string }
 */
export function validateFilePath(
  relativePath: string,
  baseDir: string,
): { safe: boolean; error?: string } {
  if (!isPathSafe(relativePath, baseDir)) {
    return { safe: false, error: "Invalid file path" };
  }

  return { safe: true };
}

/**
 * Dangerous pipe patterns - commands piped to interpreters that could execute code
 * These are checked separately to allow safe pipes (e.g., grep, head, sort)
 * while blocking dangerous ones (e.g., | bash, | python)
 */
export const DANGEROUS_PIPE_PATTERNS: BlockedPattern[] = [
  // Pipe to code interpreters — prevents prompt injection from executing arbitrary code
  { pattern: /\|\s*(ba)?sh\b/i, category: "pipe to shell" },
  { pattern: /\|\s*zsh\b/i, category: "pipe to shell" },
  { pattern: /\|\s*fish\b/i, category: "pipe to shell" },
  { pattern: /\|\s*python[23]?\b/i, category: "pipe to interpreter" },
  { pattern: /\|\s*perl\b/i, category: "pipe to interpreter" },
  { pattern: /\|\s*ruby\b/i, category: "pipe to interpreter" },
  { pattern: /\|\s*node\b/i, category: "pipe to interpreter" },
  { pattern: /\|\s*php\b/i, category: "pipe to interpreter" },
  { pattern: /\|\s*lua\b/i, category: "pipe to interpreter" },
];

/**
 * Check if a command string is safe to execute
 * Validates against both BLOCKED_PATTERNS and DANGEROUS_PIPE_PATTERNS
 *
 * @param command - The full command string to validate
 * @returns { safe: boolean, error?: string }
 */
export function isCommandSafe(command: string): { safe: boolean; error?: string } {
  // Reject empty or whitespace-only commands
  if (!command || command.trim() === "") {
    return { safe: false, error: "Empty command" };
  }

  // Check against blocked patterns
  for (const { pattern, category } of BLOCKED_PATTERNS) {
    if (pattern.test(command)) {
      return { safe: false, error: `Command blocked: ${category}` };
    }
  }

  // Check against dangerous pipe patterns
  for (const { pattern, category } of DANGEROUS_PIPE_PATTERNS) {
    if (pattern.test(command)) {
      return { safe: false, error: `Command blocked: ${category}` };
    }
  }

  return { safe: true };
}
