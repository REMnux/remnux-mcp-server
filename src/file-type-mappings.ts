/**
 * File type detection patterns.
 *
 * Maps `file` command output patterns to analysis categories.
 * Tool lists are derived from the tool registry via tags — not duplicated here.
 *
 * Derived from:
 *   - https://zeltser.com/remnux-malware-analysis-tips
 *   - https://zeltser.com/analyzing-malicious-documents
 */

/** Depth tiers for analysis. Canonical definition — import from here. */
export type DepthTier = "quick" | "standard" | "deep";

/** Ordered list of depth tiers from shallowest to deepest. */
export const DEPTH_TIER_ORDER: readonly DepthTier[] = ["quick", "standard", "deep"] as const;

export interface FileTypeCategory {
  /** Category name (e.g., "PE", "PDF") */
  name: string;
  /** Patterns matched against `file` command output (case-insensitive) */
  patterns: RegExp[];
}

export const FILE_TYPE_CATEGORIES: FileTypeCategory[] = [
  // DOTNET must precede PE: both match "PE32" but DOTNET patterns are more
  // specific (Mono/.Net, .Net assembly). First-match wins in matchFileType().
  {
    name: "DOTNET",
    patterns: [/Mono\/\.Net/i, /\.Net assembly/i, /PE32.*\.NET/i],
  },
  {
    name: "PE",
    patterns: [/PE32\+?/i, /MS-DOS executable/i],
  },
  {
    name: "PDF",
    patterns: [/\bPDF\b/i],
  },
  {
    name: "OLE2",
    patterns: [
      /Composite Document File/i,
      /OLE 2/i,
      /Microsoft Word(?! 2007)/i,
      /Microsoft Excel(?! 2007)/i,
      /Microsoft PowerPoint(?! 2007)/i,
    ],
  },
  {
    name: "OOXML",
    patterns: [
      /Microsoft Word 2007/i,
      /Microsoft Excel 2007/i,
      /\bOOXML\b/i,
    ],
  },
  {
    name: "RTF",
    patterns: [/Rich Text Format/i, /\bRTF\b/],
  },
  {
    name: "ELF",
    patterns: [/\bELF\b/],
  },
  {
    name: "OneNote",
    patterns: [/OneNote/i],
  },
  {
    name: "JavaScript",
    patterns: [/HTML document/i],
  },
  {
    name: "Script",
    patterns: [/shell script/i, /script text/i, /Python script/i, /batch file/i],
  },
  {
    name: "Python",
    patterns: [/python.*byte-compiled/i],
  },
  {
    name: "JAR",
    patterns: [/Java archive/i, /\bJAR\b/i],
  },
  {
    name: "Email",
    patterns: [/\bmail\b/i, /RFC 822/i, /\bSMTP\b/i],
  },
  {
    name: "APK",
    patterns: [/\bAndroid\b/i],
  },
  {
    name: "PCAP",
    patterns: [/pcap capture/i, /tcpdump/i, /pcapng/i, /pcap-ng/i],
  },
];

/** Maps category names to their primary registry tag. */
export const CATEGORY_TAG_MAP: Record<string, string> = {
  DOTNET: "dotnet",
  PE: "pe",
  PDF: "pdf",
  OLE2: "ole2",
  OOXML: "ooxml",
  RTF: "rtf",
  ELF: "elf",
  OneNote: "onenote",
  JavaScript: "javascript",
  Script: "script",
  Python: "python",
  JAR: "jar",
  Email: "email",
  APK: "apk",
  PCAP: "pcap",
  Memory: "memory",
  Shellcode: "shellcode",
  Unknown: "fallback",
};

/** JavaScript file extensions — used as fallback for text files. */
const JAVASCRIPT_EXTENSIONS = /\.(js|hta|wsf|html|htm)$/i;

/** Script file extensions — used as fallback for text files. */
const SCRIPT_EXTENSIONS = /\.(vbs|vbe|ps1|bat|cmd|sh|py|pl|rb)$/i;

/** Python bytecode extensions — used as fallback for data files. */
const PYTHON_EXTENSIONS = /\.(pyc|pyo)$/i;

/** PCAP file extensions — used as fallback for network captures. */
const PCAP_EXTENSIONS = /\.(pcap|pcapng|cap)$/i;

/** Memory image extensions — used as fallback when `file` reports "data". */
const MEMORY_EXTENSIONS = /\.(img|raw|mem|vmem|dmp|lime)$/i;

/** Shellcode extensions — used as fallback when `file` reports "data". */
const SHELLCODE_EXTENSIONS = /\.(bin|sc|shellcode|payload)$/i;

/** OOXML file extensions — used as fallback when `file` reports "Zip archive". */
const OOXML_EXTENSIONS = /\.(docx|docm|xlsx|xlsm|pptx|pptm)$/i;

/** OLE2 macro-enabled extensions that `file` may misidentify. */
const OLE2_EXTENSIONS = /\.(doc|xls|ppt)$/i;

/**
 * Match `file` command output to a category. Returns the first match or fallback.
 * @param fileOutput - Output from the `file` command
 * @param filename - Optional filename for extension-based fallback (e.g., when `file` says "Zip archive")
 */
export function matchFileType(fileOutput: string, filename?: string): FileTypeCategory {
  // Strip "<path>: " prefix from `file` command output (e.g., "/home/remnux/files/samples/foo.img: data" → "data")
  const typeOutput = fileOutput.includes(":") ? fileOutput.split(":").slice(1).join(":").trim() : fileOutput.trim();

  for (const category of FILE_TYPE_CATEGORIES) {
    for (const pattern of category.patterns) {
      if (pattern.test(typeOutput)) {
        return category;
      }
    }
  }

  // Fallback: extension-based classification for text files that didn't match specific patterns
  if (filename) {
    if (JAVASCRIPT_EXTENSIONS.test(filename)) {
      return FILE_TYPE_CATEGORIES.find((c) => c.name === "JavaScript")!;
    }
    if (SCRIPT_EXTENSIONS.test(filename)) {
      return FILE_TYPE_CATEGORIES.find((c) => c.name === "Script")!;
    }
    if (PYTHON_EXTENSIONS.test(filename)) {
      return FILE_TYPE_CATEGORIES.find((c) => c.name === "Python")!;
    }
  }

  // Fallback: if `file` says "Zip archive" and filename has OOXML extension, classify as OOXML
  if (filename && /zip archive/i.test(typeOutput)) {
    if (OOXML_EXTENSIONS.test(filename)) {
      return FILE_TYPE_CATEGORIES.find((c) => c.name === "OOXML")!;
    }
  }

  // Fallback: if filename has OLE2 extension and `file` output is ambiguous (e.g., "data", "CDF")
  if (filename && OLE2_EXTENSIONS.test(filename) && /^data$|^CDF/i.test(typeOutput)) {
    return FILE_TYPE_CATEGORIES.find((c) => c.name === "OLE2")!;
  }

  // Fallback: PCAP files — `file` may report "data" for some capture formats
  if (filename && PCAP_EXTENSIONS.test(filename)) {
    return FILE_TYPE_CATEGORIES.find((c) => c.name === "PCAP")!;
  }

  // Fallback: memory images — `file` reports "data" for raw memory dumps
  if (filename && MEMORY_EXTENSIONS.test(filename) && /^data$/i.test(typeOutput)) {
    return { name: "Memory", patterns: [] };
  }

  // Fallback: shellcode — `file` reports "data" and filename has shellcode extension
  if (filename && SHELLCODE_EXTENSIONS.test(filename) && /^data$/i.test(typeOutput)) {
    return { name: "Shellcode", patterns: [] };
  }

  return { name: "Unknown", patterns: [] };
}
