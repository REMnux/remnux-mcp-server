import type { HandlerDeps } from "./types.js";
import type { GetOsintGuidanceArgs } from "../schemas/tools.js";
import { formatResponse, formatError } from "../response.js";
import { toREMnuxError } from "../errors/error-mapper.js";
import { OSINT_GUIDANCE } from "../osint/guidance.js";
import {
  loadOsintCatalog,
  condensedCatalog,
  resourcesForIocType,
  type IocType,
} from "../osint/index.js";

const NOTES =
  "Server-authored, bundled, offline guidance. This tool returns GUIDANCE only — it makes no network calls and " +
  "holds no API keys; run the lookups with your own tools. The resource catalog (data/osint-resources.json) is " +
  "maintained by pull request and curated for free, mostly-stable services. The canonical source lists are " +
  "zeltser.com/automated-malware-analysis, /lookup-malicious-websites, and /malicious-ip-blocklists.";

/** Select the guidance prose for a topic. The catalog ('resources') is handled separately by ioc_type. */
function selectGuidance(topic: string): Record<string, unknown> {
  switch (topic) {
    case "tradecraft":
      return { tradecraft: OSINT_GUIDANCE.tradecraft };
    case "workflow":
      return {
        workflow_by_ioc: OSINT_GUIDANCE.workflow_by_ioc,
        disclosure_legend: OSINT_GUIDANCE.disclosure_legend,
      };
    case "access":
      return { access_guidance: OSINT_GUIDANCE.access_guidance };
    case "resources":
      return {};
    case "all":
    default:
      return {
        tradecraft: OSINT_GUIDANCE.tradecraft,
        access_guidance: OSINT_GUIDANCE.access_guidance,
        workflow_by_ioc: OSINT_GUIDANCE.workflow_by_ioc,
        disclosure_legend: OSINT_GUIDANCE.disclosure_legend,
      };
  }
}

export async function handleGetOsintGuidance(_deps: HandlerDeps, args: GetOsintGuidanceArgs) {
  const startTime = Date.now();
  try {
    const topic = args.topic ?? "all";
    const iocType = args.ioc_type as IocType | undefined;

    const data: Record<string, unknown> = {
      topic,
      version: OSINT_GUIDANCE.version,
      // Persistent header on EVERY response — leads not verdicts, corroborate, triage not assessment.
      header: OSINT_GUIDANCE.header,
      scope: OSINT_GUIDANCE.scope,
    };
    if (iocType) data.ioc_type = iocType;

    // Guidance prose, selected by `topic`.
    Object.assign(data, selectGuidance(topic));

    // Resources, selected by `ioc_type` (full detail) or `topic` (condensed / full / omitted).
    if (iocType) {
      data.resources = resourcesForIocType(iocType);
    } else if (topic === "resources") {
      data.resources = loadOsintCatalog().resources;
    } else if (topic === "all") {
      data.resources = condensedCatalog();
      data.resources_note =
        "Condensed index. The lean flow for a real sample: call once with topic='all' for the prose plus this " +
        "index, then call topic='resources' with ioc_type=<hash|url|domain|ip|family|host_artifact> per indicator " +
        "type to get full per-entry detail (caveats, both disclosure fields, stability) without re-emitting the " +
        "prose. access_guidance.first_moves lists the fastest keyless move per type.";
    }
    // Prose-only topics with no ioc_type omit `resources` entirely (token hygiene).

    data.notes = NOTES;
    return formatResponse("get_osint_guidance", data, startTime);
  } catch (error) {
    return formatError("get_osint_guidance", toREMnuxError(error), startTime);
  }
}
