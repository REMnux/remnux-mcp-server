/**
 * Preprocessors — transforms applied before analysis tools run.
 *
 * Preprocessors detect conditions (encrypted Office docs, bloated PEs,
 * PyInstaller bundles) and produce a cleaned/extracted version of the file
 * for subsequent analysis tools to operate on.
 */

export interface Preprocessor {
  /** Unique name for logging */
  name: string;
  /** Human-readable description shown in analysis output */
  description: string;
  /** File type categories this preprocessor applies to */
  categories: string[];
  /**
   * Shell command to detect whether preprocessing is needed.
   * Exit code 0 = preprocessing needed, non-zero = skip.
   */
  detectCommand: (filePath: string) => string;
  /**
   * Shell command to run the preprocessor.
   * Should write output to `outputPath`.
   */
  processCommand: (filePath: string, outputPath: string) => string;
  /** Timeout in milliseconds */
  timeout: number;
}

/** Escape a value for safe inclusion in a single-quoted shell string. */
function shellEscape(value: string): string {
  return `'${value.replace(/'/g, "'\\''")}'`;
}

export const PREPROCESSORS: Preprocessor[] = [
  {
    name: "msoffcrypto-tool",
    description: "Decrypt password-protected Office documents",
    categories: ["OLE2", "OOXML"],
    // msoffcrypto-tool -t tests if file is encrypted (exit 0 = encrypted)
    detectCommand: (fp) => `msoffcrypto-tool -t ${shellEscape(fp)}`,
    // -p "" tries empty password and the default VelvetSweatshop password
    processCommand: (fp, out) =>
      `msoffcrypto-tool -p "" ${shellEscape(fp)} ${shellEscape(out)}`,
    timeout: 30000,
  },
  {
    name: "debloat",
    description: "Remove junk from artificially bloated PE files",
    categories: ["PE", "DOTNET"],
    // Only debloat if file is >50MB
    detectCommand: (fp) =>
      `test $(stat -c%s ${shellEscape(fp)} 2>/dev/null || stat -f%z ${shellEscape(fp)}) -gt 52428800`,
    processCommand: (fp, out) =>
      `debloat -o ${shellEscape(out)} ${shellEscape(fp)}`,
    timeout: 60000,
  },
  {
    name: "pyinstxtractor",
    description: "Extract files from PyInstaller bundles",
    categories: ["PE"],
    // Check for PyInstaller magic bytes at end of file
    detectCommand: (fp) =>
      `python3 -c "import sys; f=open(sys.argv[1],'rb'); f.seek(-24,2); exit(0 if f.read(13)==b'MEI\\x0c\\x0b\\x0a\\x0b\\x0e' else 1)" ${shellEscape(fp)}`,
    processCommand: (fp, out) =>
      `pyinstxtractor ${shellEscape(fp)} -d ${shellEscape(out)}`,
    timeout: 60000,
  },
];

/**
 * Get preprocessors applicable to a given file type category.
 */
export function getPreprocessors(categoryName: string): Preprocessor[] {
  return PREPROCESSORS.filter((pp) => pp.categories.includes(categoryName));
}
