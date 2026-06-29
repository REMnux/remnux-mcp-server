import type { HandlerDeps } from "./types.js";
import type { GetReportGuidanceArgs } from "../schemas/tools.js";
import { formatResponse, formatError } from "../response.js";
import { toREMnuxError } from "../errors/error-mapper.js";
import {
  REPORT_TEMPLATE,
  GUIDELINES_DIGEST,
  ATTRIBUTION,
  SOURCE_META,
} from "../report/content.generated.js";
import { TRIAGE_DISCIPLINE } from "../report/triage-discipline.js";

const NOTES =
  "This report template and writing guidance are bundled with the server and work offline — no network required. " +
  `The canonical, continuously updated source is ${SOURCE_META.fallbackArticleUrl}. ` +
  "When online, the zeltser-website MCP server offers richer tools — malware_get_template, malware_get_guidelines, " +
  "malware_review_report, and rating_score_writing — for interactive review and scoring.";

// Maps a `topic` to the digest keys it surfaces. Keys absent from the digest are skipped.
const TOPIC_KEYS: Record<string, string[]> = {
  sections: ["longReportSections", "requiredFields", "fieldGuidance", "clarifyingQuestions"],
  confidence: ["confidence"],
  capabilities: ["capabilityModel"],
  pyramid_of_pain: ["pyramidOfPain"],
  anti_patterns: ["antiPatterns"],
  review: ["reviewGuidance", "reviewCriteria", "crossCuttingCriteria", "reviewCriteriaSectionMap"],
  writing: ["guidelines", "writingAnalysis", "audienceGuidance", "lengthGuidance", "voiceGuidelines"],
  frameworks: ["frameworks"],
  profiles: ["applicabilityProfiles"],
};

/** Return the full digest for 'all' (or unknown topics), else a scoped subset grounded by scope/limitation. */
function selectGuidelines(topic: string): Record<string, unknown> {
  if (topic === "all" || !TOPIC_KEYS[topic]) {
    return GUIDELINES_DIGEST;
  }
  const subset: Record<string, unknown> = {};
  for (const key of ["scope", "limitation", ...TOPIC_KEYS[topic]]) {
    if (key in GUIDELINES_DIGEST) subset[key] = GUIDELINES_DIGEST[key];
  }
  return subset;
}

export async function handleGetReportTemplate(_deps: HandlerDeps) {
  const startTime = Date.now();
  try {
    return formatResponse(
      "get_report_template",
      {
        template: REPORT_TEMPLATE,
        attribution: ATTRIBUTION.template,
        source: SOURCE_META,
        notes: NOTES,
      },
      startTime,
    );
  } catch (error) {
    return formatError("get_report_template", toREMnuxError(error), startTime);
  }
}

export async function handleGetReportGuidance(_deps: HandlerDeps, args: GetReportGuidanceArgs) {
  const startTime = Date.now();
  try {
    const topic = args.topic ?? "all";

    // The triage-discipline checklist is server-authored operational guidance,
    // not part of the synced report-writing digest — return it on its own.
    if (topic === "triage_checklist") {
      return formatResponse(
        "get_report_guidance",
        {
          topic,
          triage_discipline: TRIAGE_DISCIPLINE,
          notes:
            "Server-authored, bundled, offline operational guidance — distinct from the report-writing " +
            "guidelines (use any other topic, or 'all', for those).",
        },
        startTime,
      );
    }

    return formatResponse(
      "get_report_guidance",
      {
        topic,
        guidelines: selectGuidelines(topic),
        attribution: ATTRIBUTION.guidelines,
        source: SOURCE_META,
        notes: NOTES,
      },
      startTime,
    );
  } catch (error) {
    return formatError("get_report_guidance", toREMnuxError(error), startTime);
  }
}
