import type { HandlerDeps } from "./types.js";
import type { ListFilesArgs } from "../schemas/tools.js";
import { formatResponse, formatError } from "../response.js";
import { toREMnuxError } from "../errors/error-mapper.js";
import { REMnuxError } from "../errors/remnux-error.js";

export async function handleListFiles(
  deps: HandlerDeps,
  args: ListFilesArgs
) {
  const startTime = Date.now();
  const { connector, config } = deps;
  const dir = args.directory === "samples" ? config.samplesDir : config.outputDir;

  try {
    const result = await connector.execute(["ls", "-la", dir], { timeout: 30000 });

    if (result.exitCode !== 0) {
      const stderr = result.stderr || "";
      const notFound = stderr.includes("No such file") || stderr.includes("cannot access");
      return formatError("list_files", new REMnuxError(
        notFound ? `Directory does not exist: ${dir}` : `ls failed: ${stderr}`,
        notFound ? "DIR_NOT_FOUND" : "COMMAND_FAILED",
        notFound ? "not_found" : "tool_failure",
        notFound ? "Upload a file first, or check the directory path" : undefined,
      ), startTime);
    }

    const raw = result.stdout || "";

    // Parse ls -la output into structured entries
    const lines = raw.split("\n").filter((l) => l.trim() !== "");
    const entries: Array<{ name: string; size: number; date: string; type: string; permissions: string }> = [];

    for (const line of lines) {
      // Skip "total N" line
      if (line.startsWith("total ")) continue;

      // ls -la format: permissions links owner group size month day time/year name
      const match = line.match(
        /^([drwxlsStT\-]+)\s+\d+\s+\S+\s+\S+\s+(\d+)\s+(\w+\s+\d+\s+\S+)\s+(.+)$/
      );
      if (match) {
        const [, permissions, size, date, name] = match;
        // Skip . and ..
        if (name === "." || name === "..") continue;

        // Strip symlink target (e.g., "link -> /outside/sandbox/target")
        let cleanName = name;
        if (permissions.startsWith("l") && name.includes(" -> ")) {
          cleanName = name.split(" -> ")[0];
        }

        let type = "file";
        if (permissions.startsWith("d")) type = "directory";
        else if (permissions.startsWith("l")) type = "symlink";

        entries.push({
          name: cleanName,
          size: parseInt(size, 10),
          date,
          type,
          permissions,
        });
      }
    }

    return formatResponse("list_files", {
      directory: args.directory,
      path: dir,
      entries,
      entry_count: entries.length,
    }, startTime);
  } catch (error) {
    return formatError("list_files", toREMnuxError(error), startTime);
  }
}
