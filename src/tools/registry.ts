/**
 * Tool Registry — normalized tool definitions with lookup and filtering.
 *
 * All analysis tools are registered here with metadata about how to invoke them,
 * what file types they support, and what depth tier they belong to.
 */

import { TOOL_DEFINITIONS } from "./definitions.js";
import { DEPTH_TIER_ORDER } from "../file-type-mappings.js";
import type { DepthTier } from "../file-type-mappings.js";

export type InputStyle = "positional" | "flag" | "stdin";
export type OutputFormat = "text" | "json";
export type { DepthTier };

export interface ToolDefinition {
  /** Unique tool identifier (e.g., "peframe", "capa") */
  name: string;
  /** One-line description of what the tool does */
  description: string;
  /** Base command to execute (without arguments) */
  command: string;
  /** How the input file is passed to the command */
  inputStyle: InputStyle;
  /** Flag name when inputStyle is "flag" (e.g., "--input") */
  inputFlag?: string;
  /** Additional fixed arguments prepended before the file path */
  fixedArgs?: string[];
  /** Arguments appended after the file path (e.g., vol3 plugin names) */
  suffixArgs?: string[];
  /** Whether the tool requires an absolute path (vs relative) */
  requiresAbsolutePath?: boolean;
  /** Expected output format */
  outputFormat: OutputFormat;
  /** Per-tool timeout in seconds */
  timeout: number;
  /** Fallback tool names if this tool is not installed */
  alternatives?: string[];
  /** Tags for search/filtering (e.g., ["pe", "strings", "decompilation"]) */
  tags?: string[];
  /** Minimum depth tier that includes this tool */
  tier: DepthTier;
  /** Human-readable hints for specific non-zero exit codes */
  exitCodeHints?: Record<number, string>;
}

/**
 * In-memory tool registry built from static definitions.
 */
class ToolRegistry {
  private tools: Map<string, ToolDefinition>;

  constructor(definitions: ToolDefinition[]) {
    this.tools = new Map();
    for (const def of definitions) {
      this.tools.set(def.name, def);
    }
  }

  /** Get a tool by name. */
  get(name: string): ToolDefinition | undefined {
    return this.tools.get(name);
  }

  /** Get all tool definitions. */
  all(): ToolDefinition[] {
    return [...this.tools.values()];
  }

  /** Filter tools by tag. */
  byTag(tag: string): ToolDefinition[] {
    return this.all().filter((t) => t.tags?.includes(tag));
  }

  /** Filter tools by depth tier (includes all tools at or below the given tier). */
  byTier(tier: DepthTier): ToolDefinition[] {
    const maxIndex = DEPTH_TIER_ORDER.indexOf(tier);
    return this.all().filter((t) => DEPTH_TIER_ORDER.indexOf(t.tier) <= maxIndex);
  }

  /** Filter tools by tag AND depth tier. */
  byTagAndTier(tag: string, tier: DepthTier): ToolDefinition[] {
    const maxIndex = DEPTH_TIER_ORDER.indexOf(tier);
    return this.all().filter(
      (t) => t.tags?.includes(tag) && DEPTH_TIER_ORDER.indexOf(t.tier) <= maxIndex
    );
  }

  /** Check if a tool exists in the registry. */
  has(name: string): boolean {
    return this.tools.has(name);
  }

  /** Total number of registered tools. */
  get size(): number {
    return this.tools.size;
  }
}

/** Singleton registry instance. */
export const toolRegistry = new ToolRegistry(TOOL_DEFINITIONS);
