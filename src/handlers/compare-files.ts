import type { HandlerDeps } from "./types.js";
import type { CompareFilesArgs } from "../schemas/tools.js";
import type { Connector } from "../connectors/index.js";
import { validateFilePath } from "../security/blocklist.js";
import { formatResponse, formatError } from "../response.js";
import { REMnuxError } from "../errors/remnux-error.js";
import { toREMnuxError } from "../errors/error-mapper.js";
import { resolveSamplePath } from "../utils/resolve-sample-path.js";
import { checkFileExists } from "../utils/check-file-exists.js";
import { parsePeImports } from "../parsers/imports.js";
import { parseDiecOutput } from "../parsers/diec.js";
import { parseCapaOutput } from "../parsers/capa.js";
import { parseR2Sections } from "../parsers/r2.js";
import { diffFileMeta, type FileMeta } from "../analysis/file-diff.js";

/** Shannon entropy of the file's bytes, via a one-shot python helper. */
const ENTROPY_PY =
  "import sys,math,collections\n" +
  "b=open(sys.argv[1],'rb').read()\n" +
  "n=len(b) or 1\n" +
  "c=collections.Counter(b)\n" +
  "print(round(-sum((v/n)*math.log2(v/n) for v in c.values()),4))";

function archFromFileType(ft: string): string | undefined {
  if (/PE32\+|x86-64|x86_64|64-bit/i.test(ft)) return "x64";
  if (/PE32\b|Intel 80386|80386|32-bit/i.test(ft)) return "x86";
  return undefined;
}

/** Pull the value after "Type: name" from a diec finding for a given category. */
function diecValue(diecRaw: string, category: string): string | undefined {
  const parsed = parseDiecOutput(diecRaw);
  const f = parsed.findings.find((x) => x.category === category);
  if (!f) return undefined;
  const idx = f.description.indexOf(": ");
  return idx >= 0 ? f.description.slice(idx + 2) : f.description;
}

async function num(connector: Connector, cmd: string[]): Promise<number | undefined> {
  try {
    const r = await connector.execute(cmd, { timeout: 30000 });
    const n = parseFloat((r.stdout || "").trim().split(/\s+/)[0]);
    return Number.isFinite(n) ? n : undefined;
  } catch {
    return undefined;
  }
}

async function gatherFileMeta(
  connector: Connector,
  filePath: string,
  fileArg: string,
  runCapa: boolean,
): Promise<FileMeta> {
  let fileType = "";
  let sha256 = "";
  try {
    fileType = (await connector.execute(["file", filePath], { timeout: 30000 })).stdout?.trim() ?? "";
  } catch { /* best effort */ }
  try {
    sha256 = ((await connector.execute(["sha256sum", filePath], { timeout: 30000 })).stdout || "").trim().split(/\s+/)[0] || "";
  } catch { /* best effort */ }

  const size_bytes = (await num(connector, ["stat", "-c", "%s", filePath])) ?? 0;
  const entropy = await (async () => {
    try {
      const r = await connector.execute(["python3", "-c", ENTROPY_PY, filePath], { timeout: 30000 });
      const n = parseFloat((r.stdout || "").trim());
      return Number.isFinite(n) ? n : undefined;
    } catch {
      return undefined;
    }
  })();

  let compiler: string | undefined;
  let packer: string | undefined;
  try {
    const diec = (await connector.execute(["diec", "-j", filePath], { timeout: 60000 })).stdout || "";
    compiler = diecValue(diec, "compiler");
    packer = diecValue(diec, "packer") ?? diecValue(diec, "protector");
  } catch { /* best effort */ }

  let imports: string[] = [];
  try {
    const imp = parsePeImports((await connector.execute(["readpe", "-i", "-f", "json", filePath], { timeout: 60000 })).stdout || "");
    imports = imp.dlls.flatMap((d) => d.functions);
  } catch { /* non-PE or failure */ }

  let sections: string[] = [];
  try {
    const sec = parseR2Sections(
      (await connector.execute(["r2", "-2", "-q", "-N", "-e", "scr.color=0", "-c", "iSj", filePath], { timeout: 30000 })).stdout || "",
    );
    sections = sec.map((s) => s.name).filter((n) => n.length > 0);
  } catch { /* best effort */ }

  let capabilities: string[] = [];
  if (runCapa) {
    try {
      const capa = parseCapaOutput((await connector.execute(["capa", "-j", filePath], { timeout: 300000 })).stdout || "");
      capabilities = capa.findings.map((f) => f.description);
    } catch { /* best effort */ }
  }

  return {
    file: fileArg,
    file_type: fileType,
    sha256,
    size_bytes,
    arch: archFromFileType(fileType),
    entropy,
    compiler,
    packer,
    imports,
    import_count: imports.length,
    capabilities,
    capa_run: runCapa,
    sections,
  };
}

export async function handleCompareFiles(deps: HandlerDeps, args: CompareFilesArgs) {
  const startTime = Date.now();
  try {
    const { connector, config } = deps;
    const depth = args.depth ?? "standard";

    for (const f of [args.file_a, args.file_b]) {
      if (!config.noSandbox) {
        const v = validateFilePath(f, config.samplesDir);
        if (!v.safe) {
          return formatError(
            "compare_files",
            new REMnuxError(v.error || "Invalid file path", "INVALID_PATH", "validation", "Use a relative path within the samples directory"),
            startTime,
          );
        }
      }
    }

    const pa = resolveSamplePath(args.file_a, config.samplesDir, config.mode);
    const pb = resolveSamplePath(args.file_b, config.samplesDir, config.mode);
    const ea = await checkFileExists(connector, pa.filePath);
    if (ea) return formatError("compare_files", ea, startTime);
    const eb = await checkFileExists(connector, pb.filePath);
    if (eb) return formatError("compare_files", eb, startTime);

    const runCapa = depth === "standard";
    const metaA = await gatherFileMeta(connector, pa.filePath, args.file_a, runCapa);
    const metaB = await gatherFileMeta(connector, pb.filePath, args.file_b, runCapa);

    const diff = diffFileMeta(metaA, metaB);

    return formatResponse(
      "compare_files",
      {
        depth,
        basis: "Structured diff of two files' static properties (size, entropy, architecture, compiler, packer, imports, capabilities, sections). Reuses readpe/diec/capa/radare2; capability diff requires depth='standard'.",
        file_a: { ...diff.file_a, file_type: metaA.file_type, size_bytes: metaA.size_bytes, import_count: metaA.import_count },
        file_b: { ...diff.file_b, file_type: metaB.file_type, size_bytes: metaB.size_bytes, import_count: metaB.import_count },
        diff,
      },
      startTime,
    );
  } catch (error) {
    return formatError("compare_files", toREMnuxError(error, deps.config.mode), startTime);
  }
}
