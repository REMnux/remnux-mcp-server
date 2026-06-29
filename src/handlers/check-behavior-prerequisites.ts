import type { HandlerDeps } from "./types.js";
import type { CheckBehaviorPrerequisitesArgs } from "../schemas/tools.js";
import { validateFilePath } from "../security/blocklist.js";
import { formatResponse, formatError } from "../response.js";
import { REMnuxError } from "../errors/remnux-error.js";
import { toREMnuxError } from "../errors/error-mapper.js";
import { resolveSamplePath } from "../utils/resolve-sample-path.js";
import { checkFileExists } from "../utils/check-file-exists.js";
import { parsePeImports } from "../parsers/imports.js";
import {
  BEHAVIOR_PREREQUISITES,
  classifyPrerequisite,
  hasDynamicResolution,
} from "../analysis/behavior-prerequisites.js";

/** Packer/protector families whose names in diec output indicate an obscured import table. */
const PACKER_KEYWORDS =
  /\b(UPX|ASPack|MPRESS|Themida|VMProtect|Enigma|PECompact|FSG|MEW|Petite|NSPack|Armadillo|Obsidium|ASProtect|MoleBox|Yoda|kkrunchy|nspack)\b/i;

/**
 * Decide whether the import table is unreliable (packed/protected). Tries diec's
 * JSON (`detects[].values[].type` of Packer/Protector), then falls back to a
 * keyword scan of the raw output. Conservative: any signal → obscured.
 */
function looksObscured(diecOutput: string): boolean {
  const raw = diecOutput.trim();
  if (!raw) return false;
  try {
    const data = JSON.parse(raw) as { detects?: Array<{ values?: Array<{ type?: string; name?: string }> }> };
    if (Array.isArray(data.detects)) {
      for (const d of data.detects) {
        for (const v of d.values ?? []) {
          if (typeof v.type === "string" && /pack|protect/i.test(v.type)) return true;
          if (typeof v.name === "string" && PACKER_KEYWORDS.test(v.name)) return true;
        }
      }
      return false; // valid diec JSON with no packer/protector detect
    }
  } catch {
    // not JSON — fall through to keyword scan
  }
  return PACKER_KEYWORDS.test(raw);
}

const BASIS =
  "Static PE import table (readpe) plus packer detection (diec). This is a STATIC capability check: it reports " +
  "whether the binary can call the APIs a behavior requires, NOT whether the behavior runs. Static capability is " +
  "necessary but not sufficient — confirm any behavior with dynamic analysis.";

export async function handleCheckBehaviorPrerequisites(
  deps: HandlerDeps,
  args: CheckBehaviorPrerequisitesArgs,
) {
  const startTime = Date.now();
  try {
    const { connector, config } = deps;

    // Validate the requested behavior up front (clear error beats a vague result).
    const behaviorKeys = Object.keys(BEHAVIOR_PREREQUISITES);
    if (args.behavior && !(args.behavior in BEHAVIOR_PREREQUISITES)) {
      return formatError(
        "check_behavior_prerequisites",
        new REMnuxError(
          `Unknown behavior "${args.behavior}".`,
          "INVALID_ARGUMENT",
          "validation",
          `Use one of: ${behaviorKeys.join(", ")} — or omit 'behavior' to scan all.`,
        ),
        startTime,
      );
    }

    if (!config.noSandbox) {
      const validation = validateFilePath(args.file, config.samplesDir);
      if (!validation.safe) {
        return formatError(
          "check_behavior_prerequisites",
          new REMnuxError(
            validation.error || "Invalid file path",
            "INVALID_PATH",
            "validation",
            "Use a relative path within the samples directory",
          ),
          startTime,
        );
      }
    }

    const { filePath } = resolveSamplePath(args.file, config.samplesDir, config.mode);
    const fileError = await checkFileExists(connector, filePath);
    if (fileError) return formatError("check_behavior_prerequisites", fileError, startTime);

    // Confirm this is a Windows PE — the check is meaningless otherwise.
    let fileType = "";
    try {
      const r = await connector.execute(["file", filePath], { timeout: 30000 });
      fileType = r.stdout?.trim() ?? "";
    } catch (error) {
      const mapped = toREMnuxError(error, config.mode);
      if (mapped.code === "CONNECTION_FAILED") {
        return formatError("check_behavior_prerequisites", mapped, startTime);
      }
    }
    const isPe = /\bPE32\+?\b|MS Windows|for MS Windows|\.Net assembly|PE executable/i.test(fileType);
    if (!isPe) {
      return formatResponse(
        "check_behavior_prerequisites",
        {
          file: args.file,
          file_type: fileType,
          is_pe: false,
          basis: BASIS,
          results: (args.behavior ? [args.behavior] : behaviorKeys).map((b) => ({
            behavior: b,
            description: BEHAVIOR_PREREQUISITES[b].description,
            static_capability: "not_applicable",
            rationale: "Not a Windows PE file; the import-based prerequisite check does not apply.",
            recommended_followup: "Use the analysis tools appropriate for this file type.",
          })),
        },
        startTime,
      );
    }

    // Read the import table (readpe -i -f json) and detect packing (diec -j).
    let imports = parsePeImports("");
    try {
      const r = await connector.execute(["readpe", "-i", "-f", "json", filePath], { timeout: 60000 });
      imports = parsePeImports(r.stdout ?? "");
    } catch {
      // imports stays unparsed → analysis_incomplete downstream
    }

    let obscured = false;
    try {
      const r = await connector.execute(["diec", "-j", filePath], { timeout: 60000 });
      obscured = looksObscured(r.stdout ?? "");
    } catch {
      // best effort — absence of diec is not proof of no packer
    }
    // A PE that parses but imports nothing is itself a strong obscured signal.
    if (imports.parsed && imports.count === 0) obscured = true;

    // Managed/.NET: the native import table doesn't reflect managed-code
    // capability, so we must not emit a clean negative from it.
    const managed =
      /\.net assembly|mono\/\.net/i.test(fileType) ||
      imports.dlls.some((d) => /^mscoree\.dll$/i.test(d.dll));

    const ctx = { obscured, importsParsed: imports.parsed && imports.count > 0, managed };
    const keysToCheck = args.behavior ? [args.behavior] : behaviorKeys;
    const results = keysToCheck.map((b) =>
      classifyPrerequisite(b, BEHAVIOR_PREREQUISITES[b], imports.functionSet, ctx),
    );

    return formatResponse(
      "check_behavior_prerequisites",
      {
        file: args.file,
        file_type: fileType,
        is_pe: true,
        managed,
        packer_detected: obscured,
        import_count: imports.count,
        dynamic_resolution_present: hasDynamicResolution(imports.functionSet),
        basis: BASIS,
        results,
      },
      startTime,
    );
  } catch (error) {
    return formatError("check_behavior_prerequisites", toREMnuxError(error, deps.config.mode), startTime);
  }
}
