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
    await connector.execute(["true"], { timeout: 5000 });
  } catch (error) {
    return formatError("check_tools", toREMnuxError(error), startTime);
  }

  try {
    const results = await Promise.all(
      [...toolNames].map(async (name) => {
        try {
          const result = await connector.execute(["which", name], { timeout: 5000 });
          if (result.exitCode === 0 && result.stdout?.trim()) {
            return { tool: name, available: true, path: result.stdout.trim() };
          }
          return { tool: name, available: false };
        } catch {
          return { tool: name, available: false };
        }
      })
    );
    tools.push(...results);

    const available = tools.filter(t => t.available).length;
    const missing = tools.filter(t => !t.available).length;

    return formatResponse("check_tools", {
      summary: { total: tools.length, available, missing },
      tools: tools.sort((a, b) => a.tool.localeCompare(b.tool)),
    }, startTime);
  } catch (error) {
    return formatError("check_tools", toREMnuxError(error), startTime);
  }
}
