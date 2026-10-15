/**
 * Tool Catalog — complete REMnux tool inventory from salt-states.
 *
 * Provides discovery of all ~200 tools on REMnux, complementing the
 * smaller auto-run registry (~35 tools) used by analyze_file.
 */

import { readFileSync } from "node:fs";
import { resolve, dirname } from "node:path";
import { fileURLToPath } from "node:url";

export interface CatalogTool {
  command: string;
  name: string;
  category: string;
  description: string;
  website: string;
  /** Architectures stock REMnux installs the tool on. Absent means all of them. */
  architectures?: string[];
  /** Per-architecture alternative or caveat, keyed by architecture (e.g. "arm64"). */
  arch_notes?: Record<string, string>;
}

/** A tool's catalog record for one architecture of stock REMnux. */
export interface ArchStatus {
  /** False when stock REMnux does not install the tool on this architecture. */
  included: boolean;
  /** The index's note for this architecture: an alternative or a caveat. */
  note?: string;
}

/**
 * Executables installed under a different name than their catalog command, for
 * the entries whose availability or behavior differs by architecture. Lets a
 * missing executable (tracesc) be traced to its catalog entry (runsc).
 */
const ARCH_LIMITED_EXECUTABLES: Record<string, string[]> = {
  "runsc": ["tracesc"],
  "spidermonkey-patched": ["js-file", "js-ascii", "js-patched"],
  "scdbg": ["scdbgc"],
  "trid": ["tridupdate"],
  "binee-binary-emulation-environment": ["binee"],
  "malcat-lite": ["malcat"],
  "shellcode2exebat": ["shellcode2exe.bat"],
  "peepdf-3": ["peepdf"],
};

export interface ToolsIndex {
  version: string;
  updated: string;
  tools: CatalogTool[];
}

/**
 * Maps salt-states categories to MCP file-type category names.
 * Multiple salt-states categories can map to one MCP category.
 *
 * Deliberately unmapped: grab-bag salt categories such as "Gather and Analyze
 * Data", "Perform Memory Forensics", and "Explore Network Interactions: *".
 * Tools from those categories reach the AI through registry entries plus a
 * file-type category instead (volatility3 → Memory, tshark → PCAP,
 * etl-parser → ETL). Mapping a grab-bag category here would dump its unrelated
 * tools into one file type's additional_tools — do not "fix" the omission.
 */
const SALT_TO_MCP_CATEGORY: Record<string, string> = {
  // PE
  "Examine Static Properties: PE Files": "PE",
  "Statically Analyze Code: PE Files": "PE",
  "Statically Analyze Code: Unpacking": "PE",

  // .NET
  "Examine Static Properties: .NET": "DOTNET",
  "Statically Analyze Code: .NET": "DOTNET",

  // PDF
  "Analyze Documents: PDF": "PDF",

  // Office (OLE2, OOXML, RTF share tools)
  "Analyze Documents: Microsoft Office": "OLE2",

  // ELF / Go
  "Examine Static Properties: ELF Files": "ELF",
  "Examine Static Properties: Go": "ELF",
  "Dynamically Reverse-Engineer Code: ELF Files": "ELF",

  // Python
  "Statically Analyze Code: Python": "Python",

  // Scripts
  "Statically Analyze Code: Scripts": "Script",
  "Dynamically Reverse-Engineer Code: Scripts": "Script",

  // Java/JAR
  "Statically Analyze Code: Java": "JAR",

  // Email
  "Analyze Documents: Email Messages": "Email",

  // Android/APK
  "Statically Analyze Code: Android": "APK",

  // General document analysis maps to OLE2 (broad category)
  "Analyze Documents: General": "OLE2",
};

/**
 * Reverse map: MCP category → set of salt-states categories.
 */
const MCP_TO_SALT_CATEGORIES: Map<string, string[]> = new Map();
for (const [salt, mcp] of Object.entries(SALT_TO_MCP_CATEGORY)) {
  const existing = MCP_TO_SALT_CATEGORIES.get(mcp) ?? [];
  existing.push(salt);
  MCP_TO_SALT_CATEGORIES.set(mcp, existing);
}

// OOXML and RTF share Office analysis tools with OLE2
const officeCats = MCP_TO_SALT_CATEGORIES.get("OLE2") ?? [];
MCP_TO_SALT_CATEGORIES.set("OOXML", [...officeCats]);
MCP_TO_SALT_CATEGORIES.set("RTF", [...officeCats]);

export class ToolCatalog {
  private tools: CatalogTool[];
  private byMcpCategory: Map<string, CatalogTool[]>;
  private bySaltCategory: Map<string, CatalogTool[]>;
  /** Catalog entries whose availability or behavior differs by architecture, by command and executable. */
  private archLimited: Map<string, CatalogTool>;
  /** Every architecture listed in the index. An architecture outside this set never counts as limiting. */
  private knownArchitectures: Set<string>;
  readonly version: string;
  readonly updated: string;

  constructor(index: ToolsIndex) {
    this.tools = index.tools ?? [];
    this.version = index.version ?? "0.0.0";
    this.updated = index.updated ?? "unknown";

    this.knownArchitectures = new Set();
    this.archLimited = new Map();
    for (const tool of this.tools) {
      for (const arch of tool.architectures ?? []) this.knownArchitectures.add(arch);
    }
    for (const tool of this.tools) {
      const limited =
        (tool.architectures !== undefined &&
          [...this.knownArchitectures].some((a) => !tool.architectures!.includes(a))) ||
        Object.keys(tool.arch_notes ?? {}).length > 0;
      if (!limited) continue;
      for (const key of [tool.command, ...(ARCH_LIMITED_EXECUTABLES[tool.command] ?? [])]) {
        if (!this.archLimited.has(key)) this.archLimited.set(key, tool);
      }
    }

    // Index by salt-states category
    this.bySaltCategory = new Map();
    for (const tool of this.tools) {
      const existing = this.bySaltCategory.get(tool.category) ?? [];
      existing.push(tool);
      this.bySaltCategory.set(tool.category, existing);
    }

    // Index by MCP category
    this.byMcpCategory = new Map();
    for (const [mcpCat, saltCats] of MCP_TO_SALT_CATEGORIES) {
      const tools: CatalogTool[] = [];
      for (const saltCat of saltCats) {
        tools.push(...(this.bySaltCategory.get(saltCat) ?? []));
      }
      if (tools.length > 0) {
        this.byMcpCategory.set(mcpCat, tools);
      }
    }
  }

  /** All tools in the catalog. */
  all(): readonly CatalogTool[] {
    return this.tools;
  }

  /** Tools matching an MCP file-type category (PE, PDF, OLE2, etc.). */
  forMcpCategory(mcpCategory: string): CatalogTool[] {
    return this.byMcpCategory.get(mcpCategory) ?? [];
  }

  /** Tools matching a salt-states category string. */
  forSaltCategory(saltCategory: string): CatalogTool[] {
    return this.bySaltCategory.get(saltCategory) ?? [];
  }

  /** All unique salt-states categories. */
  categories(): string[] {
    return [...this.bySaltCategory.keys()].sort();
  }

  /** Total tool count. */
  get size(): number {
    return this.tools.length;
  }

  /**
   * True when a catalog command or executable differs by architecture on stock
   * REMnux. Cheap and synchronous, so callers can skip the target-architecture
   * probe for the common case.
   */
  isArchLimited(commandOrExecutable: string): boolean {
    return this.archLimited.has(commandOrExecutable);
  }

  /**
   * Stock-REMnux status of a tool on `arch`, or undefined when the catalog has
   * nothing to add: an unknown tool, an unknown or null architecture, or a tool
   * included there without a caveat. The answer covers the stock distribution.
   * Callers probe the system itself to learn whether the binary exists there.
   */
  archStatus(commandOrExecutable: string, arch: string | null): ArchStatus | undefined {
    if (!arch || !this.knownArchitectures.has(arch)) return undefined;
    const tool = this.archLimited.get(commandOrExecutable);
    if (!tool) return undefined;
    const included = tool.architectures === undefined || tool.architectures.includes(arch);
    const note = tool.arch_notes?.[arch];
    if (included && !note) return undefined;
    return { included, ...(note ? { note } : {}) };
  }

  /**
   * One or two sentences on a tool's status on `arch`, for reporting a missing
   * or limited tool, or undefined when there is nothing architecture-specific
   * to say.
   */
  archNote(commandOrExecutable: string, arch: string | null): string | undefined {
    const status = this.archStatus(commandOrExecutable, arch);
    return status ? this.formatArchNote(commandOrExecutable, arch!, status) : undefined;
  }

  /**
   * The archNote for a tool that a runtime probe found present: only the
   * caveat form (reduced function on this architecture), since a tool that is
   * there was evidently installed, whatever stock REMnux does.
   */
  limitationNote(commandOrExecutable: string, arch: string | null): string | undefined {
    const status = this.archStatus(commandOrExecutable, arch);
    return status?.included ? this.formatArchNote(commandOrExecutable, arch!, status) : undefined;
  }

  /**
   * The archNote for a tool that a runtime probe found missing: only the
   * "not included" form, since reduced function is beside the point for a
   * binary that is absent.
   */
  absenceNote(commandOrExecutable: string, arch: string | null): string | undefined {
    const status = this.archStatus(commandOrExecutable, arch);
    return status && !status.included ? this.formatArchNote(commandOrExecutable, arch!, status) : undefined;
  }

  private formatArchNote(commandOrExecutable: string, arch: string, status: ArchStatus): string {
    if (status.included) return `On ${arch} REMnux: ${status.note}`;
    const elsewhere = (this.archLimited.get(commandOrExecutable)?.architectures ?? []).join(", ");
    return (
      `Not included in stock ${arch} REMnux` +
      (elsewhere ? ` (installed on ${elsewhere} only).` : ".") +
      (status.note ? ` ${status.note}` : "")
    );
  }
}

/** Load the bundled tools-index.json. */
function loadIndex(): ToolsIndex {
  const __dirname = dirname(fileURLToPath(import.meta.url));
  // data/ is at package root, two levels up from dist/catalog/ or src/catalog/
  const indexPath = resolve(__dirname, "../../data/tools-index.json");
  const raw = readFileSync(indexPath, "utf-8");
  return JSON.parse(raw) as ToolsIndex;
}

/** Load index with graceful fallback so a missing/corrupt file doesn't crash the server. */
function loadIndexSafe(): ToolsIndex {
  try {
    return loadIndex();
  } catch (err) {
    console.error("WARNING: Failed to load tool catalog — additional_tools will be unavailable:", err);
    return { version: "0.0.0", updated: "unknown", tools: [] };
  }
}

/** Singleton catalog instance. */
export const toolCatalog = new ToolCatalog(loadIndexSafe());
