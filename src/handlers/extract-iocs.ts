import type { HandlerDeps } from "./types.js";
import type { ExtractIOCsArgs } from "../schemas/tools.js";
import { extractIOCs } from "../ioc/extractor.js";
import { formatResponse, formatError } from "../response.js";
import { toREMnuxError } from "../errors/error-mapper.js";

export async function handleExtractIOCs(
  _deps: HandlerDeps,
  args: ExtractIOCsArgs
) {
  const startTime = Date.now();

  try {
    const result = extractIOCs(args.text);

    const data: Record<string, unknown> = {
      iocs: result.iocs,
      summary: result.summary,
    };

    if (args.include_noise) {
      data.noise = result.noise;
    }

    return formatResponse("extract_iocs", data, startTime);
  } catch (error) {
    return formatError("extract_iocs", toREMnuxError(error), startTime);
  }
}
