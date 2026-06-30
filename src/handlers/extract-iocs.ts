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
    const result = extractIOCs(args.text, {
      includePrivateIPs: args.include_private_ips,
    });

    const data: Record<string, unknown> = {
      iocs: result.iocs,
      summary: result.summary,
    };

    if (args.include_noise) {
      data.noise = result.noise;
    }

    // Point the next hop at malware-specific OSINT enrichment for the IOCs just extracted.
    if (result.iocs.length > 0) {
      data.next_step =
        "To enrich these IOCs with external OSINT, call get_osint_guidance for malware-specific triage " +
        "tradecraft (hash-first, disclosure-aware) and a curated catalog of lookup services.";
    }

    return formatResponse("extract_iocs", data, startTime);
  } catch (error) {
    return formatError("extract_iocs", toREMnuxError(error), startTime);
  }
}
