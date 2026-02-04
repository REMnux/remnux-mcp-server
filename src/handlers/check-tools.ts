import type { HandlerDeps } from "./types.js";
import { toolRegistry } from "../tools/registry.js";
import { formatResponse, formatError } from "../response.js";
import { toREMnuxError } from "../errors/error-mapper.js";

export async function handleCheckTools(deps: HandlerDeps) {
  const startTime = Date.now();
  const { connector } = deps;

  // Collect unique command names from the tool registry
  const toolNames = new Set<string>();
  for (const def of toolRegistry.all()) {
    // Extract the command name (first word)
    const cmdName = def.command.split(/\s/)[0];
    toolNames.add(cmdName);
  }

  const tools: Array<{ tool: string; available: boolean; path?: string }> = [];

  // Verify container connectivity before checking individual tools
  try {
    await connector.executeShell("true", { timeout: 5000 });
  } catch (error) {
    return formatError("check_tools", toREMnuxError(error), startTime);
  }

  try {
    // Batch all tool checks in a single shell call for consistent PATH handling
    // This matches the approach used in suggest-tools.ts
    const uniqueCommands = [...toolNames];
    const availableCommands = new Map<string, string>();

    if (uniqueCommands.length > 0) {
      const checks = uniqueCommands.map((c) => `which ${c} 2>/dev/null`).join("; ");
      const result = await connector.executeShell(checks, { timeout: 30000 });

      // Parse "which" output - each line is a path if command was found
      for (const line of (result.stdout || "").split("\n")) {
        const path = line.trim();
        if (path && path.startsWith("/")) {
          // Extract command name from path (e.g., "/usr/bin/speakeasy" -> "speakeasy")
          const cmdName = path.split("/").pop();
          if (cmdName) {
            availableCommands.set(cmdName, path);
          }
        }
      }
    }

    // Build results for each tool
    const results = uniqueCommands.map((name) => {
      const path = availableCommands.get(name);
      if (path) {
        return { tool: name, available: true, path };
      }
      return { tool: name, available: false };
    });
    tools.push(...results);
  } catch {
    // Graceful degradation: mark all tools as unavailable if which calls fail
    for (const name of toolNames) {
      tools.push({ tool: name, available: false });
    }
  }

  const available = tools.filter(t => t.available).length;
  const missing = tools.filter(t => !t.available).length;

  return formatResponse("check_tools", {
    summary: { total: tools.length, available, missing },
    tools: tools.sort((a, b) => a.tool.localeCompare(b.tool)),
  }, startTime);
}
