import type { HandlerDeps } from "./types.js";
import type { VerifyStringUsageArgs } from "../schemas/tools.js";
import { validateFilePath } from "../security/blocklist.js";
import { formatResponse, formatError } from "../response.js";
import { REMnuxError } from "../errors/remnux-error.js";
import { toREMnuxError } from "../errors/error-mapper.js";
import { resolveSamplePath } from "../utils/resolve-sample-path.js";
import { checkFileExists } from "../utils/check-file-exists.js";
import { looksObscured } from "./check-behavior-prerequisites.js";
import {
  parseR2Strings,
  parseR2Sections,
  parseR2Functions,
  parseR2Xrefs,
  splitMarkedR2Output,
  R2_MARKERS,
  type R2Xref,
} from "../parsers/r2.js";
import { selectMatches, classifyMatch, type ClassifyContext } from "../analysis/string-usage.js";

const BASIS =
  "Static string enumeration (radare2 izj) plus code cross-reference analysis (aa; aar; axt). 'referenced_from_code' " +
  "means an instruction references the string; 'no_code_xrefs_detected' is a complete-analysis null result and is " +
  "NOT proof the string is unused; 'unknown' means analysis was incomplete/unreliable (packed, timed out, version " +
  "drift) and is never a negative. This is a static check — confirm runtime behavior dynamically.";

/** Base, non-interactive, hermetic r2 invocation flags. */
const R2_FLAGS = ["-2", "-q", "-N", "-e", "scr.color=0", "-e", "log.quiet=true"];

/** Total distinct string addresses fed to the (expensive) xref pass. */
const VADDR_CAP = 40;

export async function handleVerifyStringUsage(deps: HandlerDeps, args: VerifyStringUsageArgs) {
  const startTime = Date.now();
  try {
    const { connector, config } = deps;

    if (!args.query) {
      return formatError(
        "verify_string_usage",
        new REMnuxError("A non-empty 'query' string is required.", "INVALID_ARGUMENT", "validation", "Pass the string to look for."),
        startTime,
      );
    }

    if (!config.noSandbox) {
      const validation = validateFilePath(args.file, config.samplesDir);
      if (!validation.safe) {
        return formatError(
          "verify_string_usage",
          new REMnuxError(validation.error || "Invalid file path", "INVALID_PATH", "validation", "Use a relative path within the samples directory"),
          startTime,
        );
      }
    }

    const { filePath } = resolveSamplePath(args.file, config.samplesDir, config.mode);
    const fileError = await checkFileExists(connector, filePath);
    if (fileError) return formatError("verify_string_usage", fileError, startTime);

    let fileType = "";
    try {
      const r = await connector.execute(["file", filePath], { timeout: 30000 });
      fileType = r.stdout?.trim() ?? "";
    } catch (error) {
      const mapped = toREMnuxError(error, config.mode);
      if (mapped.code === "CONNECTION_FAILED") return formatError("verify_string_usage", mapped, startTime);
    }
    const isCodeFile = /\bPE32\+?\b|\bELF\b|Mach-O|MS Windows|executable/i.test(fileType);

    // Pass 1 — enumerate strings (cheap, no analysis). Try izj (mapped sections),
    // fall back to izzj (whole file). r2 absence is detected here.
    let r2Available = true;
    let strings = parseR2Strings("");
    try {
      const r = await connector.execute([...["r2"], ...R2_FLAGS, "-c", "izj", filePath], { timeout: 30000 });
      if (r.exitCode === 127 || /not found|No such file/i.test(r.stderr || "")) {
        r2Available = false;
      } else {
        strings = parseR2Strings(r.stdout || "");
        if (strings.length === 0) {
          const rz = await connector.execute([...["r2"], ...R2_FLAGS, "-c", "izzj", filePath], { timeout: 30000 });
          strings = parseR2Strings(rz.stdout || "");
        }
      }
    } catch {
      r2Available = false;
    }

    if (!r2Available) {
      return formatResponse(
        "verify_string_usage",
        {
          file: args.file, query: args.query, file_type: fileType, engine: "radare2", engine_available: false, basis: BASIS,
          match_count: 0, matches: [],
          note: "radare2 is unavailable on this system; string cross-reference analysis could not run. Status is UNKNOWN — not a 'no xref' result.",
        },
        startTime,
      );
    }

    const maxMatches = args.max_matches ?? 50;
    const { groups, truncated } = selectMatches(strings, args.query, maxMatches);

    if (groups.length === 0) {
      return formatResponse(
        "verify_string_usage",
        {
          file: args.file, query: args.query, file_type: fileType, is_code_file: isCodeFile, engine: "radare2", basis: BASIS,
          match_count: 0, matches: [],
          note: "The query was not found among this file's strings (radare2 izj/izzj). It is not embedded as a contiguous string — it could still be built at runtime or stored encoded/obfuscated.",
        },
        startTime,
      );
    }

    // Non-code file: nothing can reference the string in code.
    if (!isCodeFile) {
      const ctx: ClassifyContext = { isCodeFile: false, fileType, schemaKnown: false, analysisComplete: false, obscured: false };
      const matches = groups.map((g) => classifyMatch(g, [], [], ctx));
      return formatResponse(
        "verify_string_usage",
        { file: args.file, query: args.query, file_type: fileType, is_code_file: false, engine: "radare2", basis: BASIS, match_count: groups.length, matches_truncated: truncated, matches },
        startTime,
      );
    }

    // Detect packing (reused from check_behavior_prerequisites) — a gate for the invariant.
    let obscured = false;
    try {
      const d = await connector.execute(["diec", "-j", filePath], { timeout: 60000 });
      obscured = looksObscured(d.stdout || "");
    } catch {
      /* best effort */
    }

    // Select the groups we can afford to xref (bounded), keeping every classified
    // group fully covered so a non-queried vaddr is never read as a negative.
    const queried = new Set<number>();
    const groupsToClassify: typeof groups = [];
    for (const g of groups) {
      const vs = g.vaddrs.map((v) => v.vaddr);
      if (queried.size + vs.length > VADDR_CAP && groupsToClassify.length > 0) break;
      vs.forEach((v) => queried.add(v));
      groupsToClassify.push(g);
    }
    const matchesTruncated = truncated || groupsToClassify.length < groups.length;

    // Pass 2 — one analyzed session: version, sections, functions, per-vaddr xrefs.
    const deep = args.depth === "deep";
    const analysisCmd = deep ? "aaa" : "aa; aar";
    const parts = ["?V", analysisCmd, `?e ${R2_MARKERS.sections}`, "iSj", `?e ${R2_MARKERS.functions}`, "aflj"];
    for (const v of queried) {
      const h = "0x" + v.toString(16);
      parts.push(`?e ${R2_MARKERS.xref} ${h}`, `axtj @ ${h}`);
    }
    const soft = deep ? 60 : 20;
    let split: ReturnType<typeof splitMarkedR2Output> | undefined;
    try {
      const r = await connector.execute(
        [...["r2"], ...R2_FLAGS, "-e", `anal.timeout=${soft}`, "-c", parts.join("; "), filePath],
        { timeout: deep ? 120000 : 45000 },
      );
      split = splitMarkedR2Output(r.stdout || "");
    } catch {
      /* timeout / kill → unknown below */
    }

    if (!split) {
      const ctx: ClassifyContext = { isCodeFile: true, fileType, schemaKnown: false, analysisComplete: false, obscured };
      const matches = groupsToClassify.map((g) => classifyMatch(g, [], [], ctx));
      return formatResponse(
        "verify_string_usage",
        { file: args.file, query: args.query, file_type: fileType, is_code_file: true, engine: "radare2", packer_detected: obscured, analysis_complete: false, timed_out: true, basis: BASIS, match_count: groupsToClassify.length, matches_truncated: matchesTruncated, matches },
        startTime,
      );
    }

    const sections = parseR2Sections(split.sectionsJson);
    const functions = parseR2Functions(split.functionsJson);
    const ctx: ClassifyContext = {
      isCodeFile: true,
      fileType,
      schemaKnown: !!split.version,
      analysisComplete: !split.truncated && functions.length > 0,
      obscured,
    };

    const matches = groupsToClassify.map((g) => {
      const xrefs: R2Xref[] = [];
      let rawAnomaly = false;
      for (const v of g.vaddrs) {
        const raw = split!.xrefsByVaddr.get("0x" + v.vaddr.toString(16));
        if (raw === undefined) continue;
        const parsed = parseR2Xrefs(raw);
        const t = raw.trim();
        if (parsed.length === 0 && t !== "" && t !== "[]") rawAnomaly = true;
        xrefs.push(...parsed);
      }
      return classifyMatch(g, xrefs, sections, ctx, rawAnomaly);
    });

    return formatResponse(
      "verify_string_usage",
      {
        file: args.file, query: args.query, file_type: fileType, is_code_file: true, engine: "radare2",
        r2_version: split.version, packer_detected: obscured, analysis_complete: ctx.analysisComplete,
        basis: BASIS, match_count: groupsToClassify.length, matches_truncated: matchesTruncated, matches,
      },
      startTime,
    );
  } catch (error) {
    return formatError("verify_string_usage", toREMnuxError(error, deps.config.mode), startTime);
  }
}
