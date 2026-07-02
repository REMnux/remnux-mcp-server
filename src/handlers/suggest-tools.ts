import type { HandlerDeps } from "./types.js";
import type { SuggestToolsArgs } from "../schemas/tools.js";
import { validateFilePath } from "../security/blocklist.js";
import { matchFileType, CATEGORY_TAG_MAP } from "../file-type-mappings.js";
import type { DepthTier } from "../file-type-mappings.js";
import { toolRegistry } from "../tools/registry.js";
import { buildInvocationTemplate } from "../tools/invoker.js";
import { toolCatalog } from "../catalog/index.js";
import { formatResponse, formatError } from "../response.js";
import { REMnuxError } from "../errors/remnux-error.js";
import { toREMnuxError } from "../errors/error-mapper.js";
import { resolveSamplePath } from "../utils/resolve-sample-path.js";
import { checkFileExists } from "../utils/check-file-exists.js";

/**
 * Maps catalog command identifiers to their corresponding registry commands.
 * The catalog uses salt-states package names while the registry uses actual
 * CLI commands. One catalog entry may correspond to multiple registry tools
 * when a package ships several binaries.
 */
const CATALOG_ALIASES: Record<string, string[]> = {
  "readpe-formerly-pev": ["pescan", "pestr"],
  "ilspy": ["ilspycmd"],
  "origamindee": ["pdfcop", "pdfextract", "pdfdecompress"],
  "pdftk-java": ["pdftk"],
  "peepdf-3": ["peepdf"],
  "xlmmacrodeobfuscator": ["xlmdeobfuscator"],
  "oletools": ["oleid", "olevba", "rtfobj"],
  "decompyle": ["pycdc"],
  "pyinstaller-extractor": ["pyinstxtractor-ng"],
};

/**
 * Base per-category expert guidance for the AI agent.
 */
const BASE_HINTS: Record<string, string> = {
  DOTNET:
    "Start with peframe and diec for triage. diec detects packers/protectors. " +
    "For string extraction, pestr extracts both ASCII and Unicode with section info. " +
    "capa identifies capabilities like C2, persistence, or file manipulation. " +
    "floss extracts obfuscated strings. yara-forge scans for malware family signatures (matches indicate resemblance, not confirmed attribution). " +
    "yara-rules provides supplementary capability detection. " +
    "ilspycmd decompiles .NET to C# source. " +
    "monodis --presources lists embedded resources; --mresources extracts them. " +
    "For deep analysis, capa -vv shows matched rule details with addresses.",
  PE:
    "Start with peframe and diec for triage — diec detects packers and compilers. " +
    "For string extraction, use pestr (extracts both ASCII and Unicode with section info) — prefer over generic strings command. " +
    "capa maps capabilities to MITRE ATT&CK. floss extracts obfuscated strings. " +
    "portex provides comprehensive PE structure analysis including anomaly detection. " +
    "yara-forge scans for malware family signatures from 45+ sources (Malpedia, ReversingLabs). Matches indicate resemblance to known families, not confirmed attribution. " +
    "yara-rules provides supplementary capability/behavior detection (packers, anti-debug). " +
    "1768.py analyzes Cobalt Strike beacons. disitool.py examines Authenticode signatures. " +
    "redress recovers Go compiler info, packages, and types from Go-compiled executables — returns minimal output on non-Go PE files. " +
    "For deep analysis, capa -vv shows matched rule details with addresses. " +
    "pedump shows raw PE structure and brxor bruteforces XOR-encoded strings. " +
    "For native (non-.NET) code, r2ghidra decompiles to pseudo-C via radare2's Ghidra plugin and is function-scoped: list functions with run_tool command=\"r2 -A -q -c afl <file>\", then decompile a target with run_tool command=\"r2 -A -q -c 'pdg @ main' <file>\" ('pdg @ entry0', 'pdg @ sym.<name>', or 'pdg @ 0x<addr>'). Use 'pdc' instead of 'pdg' if the plugin is unavailable. For .NET assemblies use ilspycmd instead.",
  PDF:
    "Start with pdfid and pdfcop for triage — pdfid identifies notable elements " +
    "(/JS, /JavaScript, /OpenAction, /Launch), pdfcop detects malicious structures. " +
    "Use pdf-parser --stats for structural overview. If notable objects found, " +
    "extract them with pdf-parser -o <obj_id> -d or use pdfextract for bulk extraction " +
    "of JavaScript, attachments, and streams. " +
    "pdfdecompress strips compression filters to expose obfuscated content. " +
    "pdftool.py analyzes incremental updates — shows what changed between PDF revisions. " +
    "pdfresurrect extracts previous versions of content — recovers earlier document states. " +
    "peepdf-3 provides interactive deep analysis. " +
    "qpdf decrypts permission-locked PDFs. pdftk extracts metadata and document info.",
  OLE2:
    "Start with oleid for risk indicators (macros, encryption, external links). " +
    "olevba extracts and analyzes VBA macros — look for auto-execute triggers and notable keywords. " +
    "oledump lists OLE streams; use -s <stream> -v to dump specific macro streams. " +
    "msoffcrypto-crack.py attempts to recover passwords for encrypted documents. " +
    "pcodedmp disassembles VBA p-code (useful when source is stomped). " +
    "xlmdeobfuscator handles Excel 4.0 XLM macros.",
  OOXML:
    "olevba handles both OLE2 and OOXML macro extraction. " +
    "zipdump lists the ZIP structure — OOXML files are ZIP archives with XML inside. " +
    "To examine XML: zipdump.py -s <stream_num> -d file.docx | xmldump.py pretty. " +
    "Look for unusual entries or embedded OLE objects within the archive. " +
    "pcodedmp disassembles VBA p-code. xlmdeobfuscator deobfuscates Excel 4.0 XLM macros.",
  RTF:
    "rtfobj extracts embedded objects (OLE, packages) from RTF files. " +
    "rtfdump analyzes RTF structure and can reveal obfuscated content. " +
    "Look for embedded executables, shellcode, or CVE exploits in objects.",
  ELF:
    "readelf -h shows ELF header (type, arch, entry point). " +
    "readelf -S lists sections — look for unusual section names or sizes. " +
    "capa detects capabilities in ELF binaries similar to PE analysis. " +
    "redress analyzes Go binaries — recovers package names, types, compiler version, and source structure. On non-Go ELF files it returns minimal output (just OS/arch). " +
    "For deep analysis, capa -vv shows matched rule details with addresses. " +
    "r2ghidra decompiles ELF functions to pseudo-C (Ghidra plugin under radare2): list functions with run_tool command=\"r2 -A -q -c afl <file>\", then run_tool command=\"r2 -A -q -c 'pdg @ main' <file>\" for a target ('pdg @ sym.<name>' or 'pdg @ 0x<addr>'). 'pdc' is the native fallback if the plugin is absent.",
  JavaScript:
    "Check encoding first: run_tool command='file <file>' — modern JavaScript malware is frequently UTF-16, " +
    "and the JS analysis tools expect UTF-8/ASCII, failing or emitting garbage otherwise. On UTF-16, convert with " +
    "run_tool command='iconv -f UTF-16 -t UTF-8 > converted.js' plus input_file='<file>' (the sample path is " +
    "appended automatically and the redirect lands in the samples directory), then re-run analysis on converted.js. " +
    "js-beautify reformats the script so you can read the structure and identify the obfuscator — look for eval(), " +
    "document.write(), String.fromCharCode(), and unescape() patterns. " +
    "webcrack is the primary static deobfuscator: it unminifies, unpacks bundles, and strips obfuscator.io " +
    "protection, printing deobfuscated code to stdout. With -o <dir> it writes <dir>/deobfuscated.js instead, " +
    "but refuses to run if the directory already exists — point -o at a fresh path or clear it first, never pre-create it. " +
    "js-deobfuscator is the static fallback when webcrack leaves obfuscation behind. " +
    "webcrack is static, so values assembled at runtime stay unresolved. For those, box-js emulates the script in a " +
    "sandbox to recover runtime-built URLs and config — but it is an older tool that stalls on anti-emulation, so " +
    "reach for it deliberately (it is not in the fast standard chain), not as a first move. When you do run it, box-js " +
    "needs an absolute path to the sample, an existing parent directory for --output-dir (mkdir -p it first — the " +
    "opposite of webcrack), and a --timeout above its short 10-second default. If box-js stalls, treat the stall as a " +
    "finding — anti-emulation such as a wscript self-relaunch — and pivot back to static results (webcrack/" +
    "js-deobfuscator) or AMSI rather than retrying indefinitely. " +
    "Cross-check recovered URLs and config across webcrack and box-js (and AMSI tracing on a Windows sandbox, when " +
    "one is available): agreement raises confidence, and disagreement or a stall is itself a lead. " +
    "base64dump finds and decodes Base64 and other encoded strings. " +
    "For deep analysis, JStillery uses AST partial evaluation for deobfuscation, and " +
    "SpiderMonkey with -f /usr/share/remnux/objects.js emulates browser/PDF viewer objects. " +
    "To extract scripts from HTML, use ExtractScripts via run_tool.",
  Script:
    "base64dump finds and decodes Base64 and other encoded strings — " +
    "common in PowerShell, bash, and VBScript malware. " +
    "decode-vbe.py decodes VBE-encoded (.vbe) files only — look for #@~^ VBScript.Encode marker. " +
    "re-search extracts patterns using regular expressions (use -f flag for binary files). " +
    "For PowerShell deobfuscation, consider running pwsh via run_tool. " +
    "translate.py applies byte-level transforms. numbers-to-string.py decodes numeric payloads.",
  Python:
    "pycdc decompiles Python bytecode (.pyc) to readable source code. " +
    "uncompyle6 is an alternative decompiler supporting Python 1.0 through 3.8 — use when pycdc fails or for older Python versions. " +
    "For PyInstaller bundles, pyinstxtractor-ng extracts contents without requiring a matching Python version — invoke via run_tool.",
  JAR:
    "zipdump lists the JAR archive contents (JAR files are ZIP format). " +
    "Look for unusual class files, embedded resources, or manifest entries. " +
    "exiftool reveals metadata about the archive.",
  Email:
    "emldump analyzes EML structure and extracts attachments. " +
    "msgconvert converts Outlook MSG files to EML format for analysis with emldump. " +
    "Look for notable attachments, embedded URLs, and header anomalies. " +
    "Extract attachments for further analysis with appropriate tools.",
  Archive:
    "Compressed or password-protected archive detected. Use the extract_archive tool to unpack it — do NOT reach for raw unzip via run_tool. " +
    "extract_archive auto-tries the common malware passwords (infected, malware, virus), enforces zip-slip/path-traversal protection, and " +
    "handles WinZip AES-256 .zip and header-encrypted .7z (-mhe=on) by routing to 7z automatically. Info-ZIP unzip alone silently fails on " +
    "AES-256 zips (it skips the entries and still exits 0), which is why raw unzip is the wrong choice here. " +
    "If you already know the password, pass it as the password argument; otherwise let the auto-detection run. " +
    "After extraction, call suggest_tools or analyze_file on each extracted file to continue analysis. " +
    "For triage of the archive container itself, ssdeep gives a fuzzy hash and exiftool shows metadata.",
  APK:
    "apkid identifies compilers, packers, and obfuscators — use it for triage alongside droidlysis to understand what protections are applied. " +
    "apktool decompiles the APK to smali and extracts resources. " +
    "droidlysis performs static analysis identifying permissions, API calls, and risk indicators. " +
    "Look for excessive permissions, obfuscation, and notable network activity.",
  OneNote:
    "OneNote file detected. onedump.py analyzes OneNote documents and extracts embedded files. " +
    "Use strings and exiftool for additional triage. " +
    "OneNote files may contain embedded scripts, executables, or malicious attachments.",
  Shellcode:
    "Raw shellcode detected. speakeasy emulates both x86 and x64 shellcode with Windows API emulation. " +
    "Look for resolved API names, network connections, file system access, and registry modifications in emulation output. " +
    "For deep analysis, qltool (Qiling) provides multi-platform emulation and tracesc traces execution via Wine. " +
    "Use strings and xorsearch for static indicators before emulation.",
  Memory:
    "Memory image detected. Start with vol3-info to identify OS and kernel version. " +
    "vol3-pslist and vol3-pstree reveal running processes. " +
    "vol3-netscan shows network connections. vol3-psscan finds hidden/unlinked processes. " +
    "vol3-cmdline extracts process arguments. vol3-dlllist shows loaded DLLs. " +
    "vol3-filescan finds file objects. vol3-hivelist lists registry hives. " +
    "For deeper analysis, vol3-malfind detects injected code and vol3-handles lists open handles. " +
    "For Linux memory images, use vol3-linux-pslist.",
  Unknown:
    "File type not recognized. strings and exiftool provide basic triage. " +
    "base64dump searches for encoded content. xorsearch.py outputs JSON for structured analysis; xorsearch binary is faster for large files. " +
    "translate.py applies byte-level transforms (XOR, shift). re-search.py extracts regex patterns. " +
    "file-magic.py identifies embedded file types. numbers-to-string.py decodes numeric payloads. " +
    "cut-bytes.py extracts byte ranges. format-bytes.py parses structured binary data. " +
    "xor-kpa.py performs known-plaintext XOR attacks. " +
    "Consider using 'file' or 'diec' via run_tool for deeper type identification.",
  DataWithPEExtension:
    "File has an executable extension but 'file' reports 'data' — may be raw shellcode, " +
    "packed/encrypted payload, or corrupted PE. Start with strings and xorsearch for static indicators. " +
    "speakeasy emulates both PE files and raw shellcode — try x86 first, then amd64. " +
    "1768.py and csce detect Cobalt Strike beacon configs. " +
    "If emulation produces no output, the file may be encrypted — try base64dump for encoded content.",
};

/** Observable properties extracted from `file` command output. */
interface FileProperties {
  packed?: string;       // Packer name if detected
  isDotNet?: boolean;
  isDll?: boolean;
  compiler?: string;
  fileSize?: number;     // bytes
}

/** Extract observable properties from `file` command output. */
function extractFileProperties(fileOutput: string): FileProperties {
  const lower = fileOutput.toLowerCase();
  const props: FileProperties = {};

  if (/upx/i.test(fileOutput)) props.packed = "UPX";
  else if (/aspack/i.test(fileOutput)) props.packed = "ASPack";
  else if (/pecompact/i.test(fileOutput)) props.packed = "PECompact";
  else if (/themida/i.test(fileOutput)) props.packed = "Themida";

  if (lower.includes(".net") || lower.includes("mono/") || lower.includes("msil")) {
    props.isDotNet = true;
  }

  if (lower.includes("(dll)") || lower.includes("dll ")) {
    props.isDll = true;
  }

  if (/purebasic/i.test(fileOutput)) props.compiler = "PureBasic";
  else if (/masm/i.test(fileOutput)) props.compiler = "MASM";
  else if (/delphi/i.test(fileOutput)) props.compiler = "Delphi";
  else if (/autoit/i.test(fileOutput)) props.compiler = "AutoIt";

  return props;
}

/** Generate dynamic hints by augmenting base hints with property-specific guidance. */
function generateHints(category: string, fileOutput: string): string {
  const base = BASE_HINTS[category] ?? BASE_HINTS.Unknown;
  const props = extractFileProperties(fileOutput);
  const extras: string[] = [];

  if (props.packed) {
    extras.push(
      `Packer detected: ${props.packed}. ` +
      "capa and floss results may be limited on packed samples. " +
      (props.packed === "UPX"
        ? "UPX can be unpacked with the upx-decompress tool — recommend unpacking then re-analyzing."
        : "No standard unpacker available; static code analysis will be limited. " +
          "Focus on: certificate/signature artifacts (disitool.py for structure, pestr for embedded text including Unicode), " +
          "metadata masquerading (exiftool, peframe), and string patterns for C2/IOCs."),
    );
  }

  if (props.isDotNet) {
    extras.push("Detected .NET assembly — ilspycmd decompilation recommended for source-level analysis. monodis --presources lists embedded resources (payloads, config data).");
  }

  if (props.isDll) {
    extras.push("DLL detected — check exports with `pedump --exports` for entry point analysis.");
  }

  if (props.compiler === "AutoIt") {
    extras.push(
      "AutoIt compiled executable detected. " +
      "autoit-ripper extracts and decompiles the embedded script to .au3 source. " +
      "Review the decompiled script for C2 URLs, obfuscated strings, and DllCall APIs."
    );
  } else if (props.compiler) {
    extras.push(`Unusual compiler: ${props.compiler}. This may indicate specialized tooling or uncommon origin.`);
  }

  if (extras.length === 0) return base;
  return base + "\n\nAdditional notes: " + extras.join(" ");
}

export async function handleSuggestTools(
  deps: HandlerDeps,
  args: SuggestToolsArgs,
) {
  const startTime = Date.now();
  try {
  const { connector, config } = deps;
  const depth = (args.depth ?? "standard") as DepthTier;

  // Validate file path (skip unless --sandbox)
  if (!config.noSandbox) {
    const validation = validateFilePath(args.file, config.samplesDir);
    if (!validation.safe) {
      return formatError("suggest_tools", new REMnuxError(
        validation.error || "Invalid file path",
        "INVALID_PATH",
        "validation",
        "Use a relative path within the samples directory",
      ), startTime);
    }
  }

  const { filePath, normalizedFile } = resolveSamplePath(args.file, config.samplesDir, config.mode);

  // Check file exists before running commands
  const fileError = await checkFileExists(connector, filePath);
  if (fileError) return formatError("suggest_tools", fileError, startTime);

  // Detect file type
  let fileOutput: string;
  try {
    const result = await connector.execute(["file", filePath], { timeout: 30000 });
    fileOutput = result.stdout?.trim() || "";
    if (!fileOutput) {
      return formatError("suggest_tools", new REMnuxError(
        "Could not determine file type (empty `file` output)",
        "EMPTY_OUTPUT",
        "tool_failure",
        "Check that the file exists and is readable",
      ), startTime);
    }
  } catch (error) {
    const msg = `Error running file command: ${error instanceof Error ? error.message : "Unknown error"}`;
    return formatError("suggest_tools", new REMnuxError(
      msg,
      "EMPTY_OUTPUT",
      "tool_failure",
      "Check that the file exists and is readable",
    ), startTime);
  }

  // Match category and get tools from registry
  const category = matchFileType(fileOutput, normalizedFile);

  const primaryTag = CATEGORY_TAG_MAP[category.name] ?? "fallback";
  const tools = toolRegistry.byTagAndTier(primaryTag, depth);

  // Check tool availability (batch all unique commands in one shell call)
  const uniqueCommands = [...new Set(tools.map((t) => t.command))];
  const availableCommands = new Set<string>();
  if (uniqueCommands.length > 0) {
    try {
      // Single shell call: check all commands at once
      const checks = uniqueCommands.map((c) => `which ${c} >/dev/null 2>&1 && echo "${c}"`).join("; ");
      const check = await connector.executeShell(checks, {
        timeout: 10000,
        cwd: config.samplesDir,
      });
      for (const line of (check.stdout || "").split("\n")) {
        const cmd = line.trim();
        if (cmd) availableCommands.add(cmd);
      }
    } catch {
      // On failure, assume all available (graceful degradation)
      for (const c of uniqueCommands) availableCommands.add(c);
    }
  }

  const recommended = tools.map((t) => ({
    name: t.name,
    invocation: buildInvocationTemplate(t),
    description: t.description,
    tier: t.tier,
    tags: t.tags ?? [],
    ...(availableCommands.has(t.command) ? {} : { available: false as const }),
  }));

  // Query catalog for additional tools not in the registry
  let additionalTools: Array<{ name: string; description: string; website: string }> = [];
  try {
    const normalize = (c: string) => c.replace(/\.py$/, '');
    const registryCommands = new Set(tools.map((t) => normalize(t.command)));

    // Check if a catalog tool is already covered by the registry
    const isCovered = (catalogCmd: string): boolean => {
      // Direct match (with .py normalization)
      if (registryCommands.has(normalize(catalogCmd))) return true;
      // Alias match (catalog package name → registry CLI commands)
      // Alias match: catalog package name → registry CLI commands.
      // Uses some() deliberately: if ANY tool from the package is recommended,
      // the catalog package entry is hidden to avoid confusing overlap.
      const aliases = CATALOG_ALIASES[catalogCmd];
      return aliases !== undefined && aliases.some((a) => registryCommands.has(normalize(a)));
    };

    const seen = new Set<string>();
    additionalTools = toolCatalog.forMcpCategory(category.name)
      .filter((ct) => !isCovered(ct.command))
      .filter((ct) => {
        if (seen.has(ct.command)) return false;
        seen.add(ct.command);
        return true;
      })
      .map((ct) => ({
        name: ct.name,
        description: ct.description,
        website: ct.website,
      }));
  } catch (err) {
    console.error("WARNING: Catalog query failed for additional_tools:", err);
  }

  return formatResponse("suggest_tools", {
    file: args.file,
    detected_type: fileOutput,
    matched_category: category.name,
    depth,
    recommended_tools: recommended,
    ...(recommended.length > 0 && {
      invocation_note:
        "Each tool's `invocation` is the exact command for run_tool: replace `<file>` with the sample path, and pass `%OUTPUT%/` through literally (the server resolves it to the session output directory).",
    }),
    ...(recommended.length === 0 && {
      warning: `No tools registered for category "${category.name}" at depth "${depth}". Try depth "deep" or use run_tool directly.`,
    }),
    analysis_hints: generateHints(category.name, fileOutput),
    ...(additionalTools.length > 0 && {
      additional_tools: additionalTools,
      additional_tools_note:
        "Other tools installed on REMnux for this file type, beyond those analyze_file auto-runs. " +
        "These are discovery pointers (name, purpose, docs link) — not runnable commands. " +
        "To use one, get its exact command from the linked docs, then run_tool it.",
    }),
  }, startTime);
  } catch (error) {
    return formatError("suggest_tools", toREMnuxError(error, deps.config.mode), startTime);
  }
}
