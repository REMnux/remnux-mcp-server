/**
 * Session-level state for tracking archive metadata across tool calls.
 *
 * When extract_archive succeeds, we store the format and password used.
 * When download_file runs with archive: true, we look up matching metadata
 * to re-use the same format and password for the download archive.
 */

import { basename } from "path";

export const DEFAULT_ARCHIVE_PASSWORD = "infected";
export const DEFAULT_ARCHIVE_FORMAT = "zip" as const;

export interface ArchiveMetadata {
  format: "zip" | "7z" | "rar";
  password: string;
}

export class SessionState {
  /**
   * Maps sample filenames to the archive metadata from their extraction.
   * Keys include both the archive filename and each extracted filename.
   */
  private archiveInfo = new Map<string, ArchiveMetadata>();

  /**
   * Store archive metadata after a successful extraction.
   *
   * @param archiveFile - The archive filename (e.g., "sample.zip")
   * @param extractedFiles - List of extracted filenames
   * @param format - Archive format used
   * @param password - Password that worked (empty string if none)
   */
  storeArchiveInfo(
    archiveFile: string,
    extractedFiles: string[],
    format: ArchiveMetadata["format"],
    password: string
  ): void {
    const meta: ArchiveMetadata = { format, password };
    this.archiveInfo.set(archiveFile, meta);
    for (const file of extractedFiles) {
      this.archiveInfo.set(file, meta);
      // Also store by basename so download_file can look up by basename(file_path)
      const base = basename(file);
      if (base !== file) {
        this.archiveInfo.set(base, meta);
      }
    }
  }

  /**
   * Look up archive metadata for a given filename.
   * Returns undefined if no metadata was stored for this file.
   */
  getArchiveInfo(filename: string): ArchiveMetadata | undefined {
    return this.archiveInfo.get(filename);
  }
}
