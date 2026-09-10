/**
 * Shell-free executable resolution that never consults the current directory.
 *
 * WHY THIS EXISTS
 *
 * Handing a bare program name to child_process.execFile/spawn is not neutral on
 * Windows. libuv's uv_spawn resolves it with its own search, and from
 * libuv/src/win/process.c:
 *
 *   "- If there's really only a filename, check the current directory for file,
 *      then search all path directories."
 *
 *   if (NeedCurrentDirectoryForExePathW(L"")) {
 *     // The file is really only a name; look in cwd first, then scan path
 *
 * That branch is taken unless the NoDefaultCurrentDirectoryInExePath environment
 * variable is set, which it is not by default. libuv also appends ".com" before
 * ".exe" (path_search_walk_ext), so a planted `docker.com` wins over a genuine
 * `docker.exe` sitting on PATH.
 *
 * This matters here specifically: an analyst plausibly runs their AI client from
 * a directory where a malware sample was unpacked, which makes the process cwd
 * attacker-influenced. A sample that drops `docker.com` next to itself would then
 * be executed by this server, on the host, outside the container isolation the
 * threat model depends on.
 *
 * Passing a FULLY QUALIFIED path removes the search entirely. libuv takes its
 * `file_has_dir` branch (which consults neither cwd nor PATH), and
 * search_path_join_test zeroes the cwd for an absolute path with a drive letter.
 *
 * The resolution below is therefore deliberately stricter than the platform's:
 * only fully qualified PATH directories are considered, so no candidate can ever
 * depend on where the process happens to be running.
 *
 * SCOPE. This removes cwd-dependent DISCOVERY of the executable. It does not
 * establish that the resolved binary is trustworthy: a PATH directory writable by
 * the attacker is still a PATH directory, and DLL search order for the resolved
 * executable is the Windows loader's business, not ours.
 */

import { accessSync, statSync, constants } from "fs";

export interface ResolveExecutableOptions {
  /** Raw PATH value. Undefined or empty means "do not guess" — resolution fails. */
  pathEnv: string | undefined;
  platform: NodeJS.Platform;
  /**
   * Existence/executability probe. Injectable so both platform branches can be
   * exercised on any runner; defaults to a real filesystem check.
   */
  isExecutableFile?: (candidate: string) => boolean;
}

/**
 * True only for a path that resolves identically regardless of the process's
 * current directory AND current drive.
 *
 * `path.win32.isAbsolute()` is NOT usable for this: it returns true for "\tools"
 * and "/tools", which libuv resolves against the current drive
 * (search_path_join_test sets cwd_len = 2 for them), leaving cwd in play.
 */
export function isFullyQualified(entry: string, platform: NodeJS.Platform): boolean {
  if (!entry) return false;

  if (platform !== "win32") {
    return entry.startsWith("/");
  }

  // UNC: \\server\share or //server/share
  if (/^[\\/]{2}[^\\/]/.test(entry)) return true;

  // Drive-qualified: X:\... or X:/... — the separator after the colon is what
  // separates this from the drive-RELATIVE "C:tools", which resolves against
  // that drive's own working directory.
  if (/^[A-Za-z]:[\\/]/.test(entry)) return true;

  return false;
}

/**
 * Split a raw PATH value into entries.
 *
 * Windows PATH entries may be quoted, and a quoted entry may itself contain the
 * ';' delimiter — a naive split corrupts those. Empty entries are dropped: on
 * both platforms an empty entry means "the current directory".
 */
export function splitPathEnv(
  pathEnv: string | undefined,
  platform: NodeJS.Platform,
): string[] {
  if (!pathEnv) return [];

  const delimiter = platform === "win32" ? ";" : ":";
  const entries: string[] = [];
  let current = "";
  let quote: string | null = null;
  let atEntryStart = true;

  for (const ch of pathEnv) {
    // libuv only honours a quote that OPENS an entry:
    //   dir_start = dir_end; if (*dir_start == L'"' || *dir_start == L'\'') ...
    // Treating a quote anywhere would make an apostrophe in an ordinary
    // directory name (C:\Users\O'Brien\bin) swallow the following delimiter and
    // merge it with the next entry, hiding a real Docker installation.
    if (platform === "win32" && atEntryStart && quote === null && (ch === '"' || ch === "'")) {
      quote = ch;
      atEntryStart = false;
      continue;
    }
    if (quote !== null && ch === quote) {
      quote = null;
      continue;
    }
    if (ch === delimiter && quote === null) {
      entries.push(current);
      current = "";
      atEntryStart = true;
      continue;
    }
    current += ch;
    atEntryStart = false;
  }
  entries.push(current);

  // Whitespace: cmd.exe preserves it, and so do we on POSIX, where a trailing
  // space is a legal part of a directory name and trimming would silently point
  // at a different directory. On Windows a path component cannot end in a space
  // (the API strips it), while "C:\a; C:\b" spacing is common in real PATHs, so
  // trimming there only helps find Docker and can never widen what we accept:
  // every entry still has to clear isFullyQualified.
  const cleaned = platform === "win32" ? entries.map((e) => e.trim()) : entries;
  return cleaned.filter((e) => e.length > 0);
}

/**
 * Candidate filenames to try inside each directory, in libuv's order.
 *
 * From path_search_walk_ext: the literal name is tried first ONLY when it
 * already carries a non-empty extension, then ".com" is appended, then ".exe".
 * A bare "docker" is therefore never tried as an extensionless file, because
 * CreateProcess cannot run one.
 */
export function candidateNames(name: string, platform: NodeJS.Platform): string[] {
  if (platform !== "win32") return [name];

  // libuv uses wcschr — the FIRST dot, not the last — and requires a character
  // after it for the name to count as already having an extension.
  const dot = name.indexOf(".");
  const hasExtension = dot !== -1 && dot < name.length - 1;

  // "Add a dot if the filename didn't end with one": a name already ending in a
  // dot reuses it rather than gaining a second.
  const join = (ext: string) =>
    name.endsWith(".") ? `${name}${ext}` : `${name}.${ext}`;

  return hasExtension
    ? [name, join("com"), join("exe")]
    : [join("com"), join("exe")];
}

function defaultIsExecutableFile(
  candidate: string,
  platform: NodeJS.Platform,
): boolean {
  try {
    // statSync follows symlinks, which is required: package managers and Docker
    // Desktop both install the CLI as a symlink in common setups.
    if (!statSync(candidate).isFile()) return false;
    if (platform === "win32") return true;
    accessSync(candidate, constants.X_OK);
    return true;
  } catch {
    return false;
  }
}

/**
 * Resolve a bare executable name to a fully qualified path using PATH only.
 *
 * Returns null when nothing is found. Callers MUST NOT fall back to the bare
 * name on null: that hands resolution straight back to the cwd-first search
 * this function exists to bypass.
 */
export function resolveExecutable(
  name: string,
  options: ResolveExecutableOptions,
): string | null {
  const { pathEnv, platform } = options;
  const probe =
    options.isExecutableFile ?? ((c: string) => defaultIsExecutableFile(c, platform));

  const separator = platform === "win32" ? "\\" : "/";
  const candidates = candidateNames(name, platform);

  for (const entry of splitPathEnv(pathEnv, platform)) {
    if (!isFullyQualified(entry, platform)) continue;

    // Strip one trailing separator so we do not emit a doubled one. Backslash
    // counts only on Windows: on POSIX it is an ordinary filename character,
    // and treating it as a separator would point at a different directory.
    const isTrailingSeparator =
      entry.endsWith("/") || (platform === "win32" && entry.endsWith("\\"));
    const base = isTrailingSeparator ? entry.slice(0, -1) : entry;

    for (const candidate of candidates) {
      const full = `${base}${separator}${candidate}`;
      if (probe(full)) return full;
    }
  }

  return null;
}
