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
}

export interface ToolsIndex {
  version: string;
  updated: string;
  tools: CatalogTool[];
}

/**
 * Maps salt-states categories to MCP file-type category names.
 * Multiple salt-states categories can map to one MCP category.
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

class ToolCatalog {
  private tools: CatalogTool[];
  private byMcpCategory: Map<string, CatalogTool[]>;
  private bySaltCategory: Map<string, CatalogTool[]>;
  readonly version: string;
  readonly updated: string;

  constructor(index: ToolsIndex) {
    this.tools = index.tools ?? [];
    this.version = index.version ?? "0.0.0";
    this.updated = index.updated ?? "unknown";

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
