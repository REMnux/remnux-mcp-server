/**
 * Static behavior-prerequisite analysis.
 *
 * Answers "can this binary even call the APIs that behavior X requires?" from
 * the static import table. This is a deliberate GATE against the most common
 * triage error — claiming a behavior on artifact evidence alone — by forcing an
 * explicit "are the prerequisite APIs accessible?" check.
 *
 * Design constraints (from the project's design review):
 *  - It reports a STATIC-capability assessment, never a behavioral verdict. The
 *    field is `static_capability` (not `verdict`) and every value is suffixed
 *    with the basis (`_statically`) so it cannot be misread as "the sample does
 *    X". Static capability is necessary, not sufficient, for the behavior.
 *  - It never emits a clean "incapable" on a packed/obscured binary — the
 *    import table is unreliable there, so it returns `analysis_incomplete`
 *    ("unpack first") rather than a false negative.
 *  - When the required APIs are absent but GetProcAddress + a library loader are
 *    present, it returns `possibly_via_dynamic_resolution` — it cannot prove
 *    those resolvers are NOT used to reach the missing APIs without xref /
 *    dynamic analysis, so it does not claim `incapable_statically`.
 *  - The behavior→API table is generic malware-analysis knowledge, not tuned to
 *    any specific sample.
 */

import { apiPresent } from "../parsers/imports.js";

export type StaticCapability =
  | "capable_statically"
  | "incapable_statically"
  | "possibly_via_dynamic_resolution"
  | "analysis_incomplete"
  | "not_applicable";

export interface BehaviorDef {
  /** Human-readable description of the behavior. */
  description: string;
  /** Required API base names (no ANSI/Unicode suffix). */
  apis: string[];
  /** How many of `apis` must be present to call the binary statically capable. */
  minMatch: number;
}

/**
 * Behavior → prerequisite APIs. Base names only (apiPresent handles A/W). The
 * minMatch threshold tolerates that a behavior rarely needs its entire API set
 * and that import names vary, while still requiring a meaningful signature.
 */
export const BEHAVIOR_PREREQUISITES: Record<string, BehaviorDef> = {
  clipboard_hijacking: {
    description: "Read and/or replace clipboard contents (e.g. a crypto clipper).",
    apis: ["OpenClipboard", "GetClipboardData", "SetClipboardData", "EmptyClipboard"],
    minMatch: 2,
  },
  http_c2_wininet: {
    description: "HTTP(S) command-and-control or download via the WinINet API.",
    apis: ["InternetOpen", "InternetConnect", "InternetOpenUrl", "HttpOpenRequest", "HttpSendRequest", "HttpQueryInfo", "InternetReadFile"],
    minMatch: 2,
  },
  winhttp_c2: {
    description: "HTTP(S) command-and-control or download via the WinHTTP API.",
    apis: ["WinHttpOpen", "WinHttpConnect", "WinHttpOpenRequest", "WinHttpSendRequest", "WinHttpReceiveResponse", "WinHttpReadData"],
    minMatch: 2,
  },
  socket_c2: {
    description: "Raw-socket network communication (Winsock).",
    apis: ["WSAStartup", "socket", "connect", "send", "recv", "WSASend", "WSARecv"],
    minMatch: 3,
  },
  process_injection_remote: {
    description: "Inject code into another process (remote injection).",
    apis: ["OpenProcess", "VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread", "NtCreateThreadEx", "QueueUserAPC", "NtMapViewOfSection", "NtWriteVirtualMemory"],
    minMatch: 3,
  },
  process_injection_self: {
    description: "Allocate, write, and execute code in the binary's own process.",
    apis: ["VirtualAlloc", "VirtualProtect", "WriteProcessMemory", "NtProtectVirtualMemory"],
    minMatch: 2,
  },
  registry_persistence_run: {
    description: "Persist via a registry Run key (or similar).",
    apis: ["RegOpenKeyEx", "RegCreateKeyEx", "RegSetValueEx"],
    minMatch: 2,
  },
  lnk_persistence: {
    description: "Create a shortcut (.lnk) for persistence via IShellLink (COM).",
    apis: ["CoCreateInstance", "CoInitialize", "CoInitializeEx"],
    minMatch: 1,
  },
  browser_credential_theft: {
    description: "Decrypt DPAPI-protected secrets (browser logins, wallets).",
    apis: ["CryptUnprotectData"],
    minMatch: 1,
  },
  screen_capture: {
    description: "Capture the screen via GDI.",
    apis: ["GetDC", "GetDesktopWindow", "CreateCompatibleDC", "CreateCompatibleBitmap", "BitBlt", "GetDIBits"],
    minMatch: 3,
  },
  keylog_polling: {
    description: "Log keystrokes by polling key state.",
    apis: ["GetAsyncKeyState", "GetKeyState", "GetKeyboardState"],
    minMatch: 1,
  },
  keylog_hook: {
    description: "Log keystrokes via a Windows hook.",
    apis: ["SetWindowsHookEx"],
    minMatch: 1,
  },
  network_share_enum: {
    description: "Enumerate network shares / servers.",
    apis: ["NetShareEnum", "NetServerEnum", "WNetEnumResource", "WNetOpenEnum"],
    minMatch: 1,
  },
};

/** Primitives that allow resolving APIs at runtime instead of importing them. */
const DYNAMIC_RESOLVERS = ["GetProcAddress"];
const LIBRARY_LOADERS = ["LoadLibrary", "LoadLibraryEx", "LdrLoadDll", "LdrGetProcedureAddress"];

export interface PrerequisiteResult {
  behavior: string;
  description: string;
  required_apis: string[];
  apis_present: string[];
  apis_missing: string[];
  dynamic_resolution_present: boolean;
  static_capability: StaticCapability;
  rationale: string;
  recommended_followup: string;
}

/** Context derived from the binary (packer detection, whether imports parsed). */
export interface PrerequisiteContext {
  /** A packer/protector was detected, or the import table is unreadable/empty. */
  obscured: boolean;
  /** readpe produced a usable import table. */
  importsParsed: boolean;
  /** Managed/.NET assembly — native imports don't reflect managed-code capability. */
  managed?: boolean;
}

function followupFor(verdict: StaticCapability): string {
  switch (verdict) {
    case "capable_statically":
      return "Static capability only. Confirm the behavior at runtime (speakeasy emulation or sandbox detonation) and verify the imported APIs are called from reachable code.";
    case "possibly_via_dynamic_resolution":
      return "Cannot rule out runtime API resolution. Xref the GetProcAddress calls or detonate dynamically to see which APIs are actually resolved.";
    case "incapable_statically":
      return "No static support found. If you still suspect this behavior, the sample may resolve APIs in a way static imports miss — detonate dynamically to be sure (static analysis cannot prove a negative under obfuscation).";
    case "analysis_incomplete":
      return "Unpack the sample (e.g. 'upx -d', or dump it from a sandbox) and re-run this check on the unpacked binary; the visible import table is not the real one.";
    case "not_applicable":
      return "This check applies to Windows PE files. Use the analysis tools appropriate for this file type.";
  }
}

/** Detect the GetProcAddress + library-loader pair that enables runtime resolution. */
export function hasDynamicResolution(functionSet: Set<string>): boolean {
  return (
    DYNAMIC_RESOLVERS.some((a) => apiPresent(a, functionSet)) &&
    LIBRARY_LOADERS.some((a) => apiPresent(a, functionSet))
  );
}

/**
 * Classify one behavior against an import set + context. Pure and deterministic.
 */
export function classifyPrerequisite(
  behaviorKey: string,
  def: BehaviorDef,
  functionSet: Set<string>,
  ctx: PrerequisiteContext,
): PrerequisiteResult {
  const present = def.apis.filter((a) => apiPresent(a, functionSet));
  const missing = def.apis.filter((a) => !apiPresent(a, functionSet));
  const dynamicResolutionPresent = hasDynamicResolution(functionSet);

  let static_capability: StaticCapability;
  let rationale: string;
  let recommended_followup: string;

  if (present.length >= def.minMatch) {
    static_capability = "capable_statically";
    rationale =
      `${present.length} of ${def.apis.length} prerequisite APIs are statically imported ` +
      `(${present.join(", ")}). The binary CAN make these calls; this is not evidence the behavior ` +
      `executes at runtime.`;
    recommended_followup = followupFor(static_capability);
  } else if (ctx.managed) {
    // A .NET/managed binary calls the framework, not native APIs — the native
    // import table can't establish capability, so don't emit a false negative.
    static_capability = "analysis_incomplete";
    rationale =
      "This is a managed/.NET assembly; native API imports do not reflect managed-code capability (a .NET " +
      "program calls the framework, e.g. System.Windows.Forms.Clipboard, rather than importing native APIs). " +
      "A clean negative cannot be given from the native import table.";
    recommended_followup =
      "Analyze as .NET: decompile with ilspycmd or dnSpy and look for the relevant framework calls " +
      "(e.g. System.Windows.Forms.Clipboard, System.Net.Http, Microsoft.Win32.Registry).";
  } else if (ctx.obscured || !ctx.importsParsed) {
    static_capability = "analysis_incomplete";
    rationale = ctx.importsParsed
      ? "The binary appears packed/obscured, so the import table does not reflect its real API surface. A clean negative cannot be given until it is unpacked."
      : "The PE import table could not be read, so static capability cannot be assessed.";
    recommended_followup =
      "Unpack the sample (e.g. 'upx -d', or dump it from a sandbox) and re-run this check on the unpacked " +
      "binary; the visible import table is not the real one.";
  } else if (dynamicResolutionPresent) {
    static_capability = "possibly_via_dynamic_resolution";
    rationale =
      "The prerequisite APIs are not statically imported, but GetProcAddress and a library loader are present, " +
      "so the APIs could be resolved at runtime. Static imports alone cannot rule this out — proving which APIs " +
      "are resolved requires cross-reference or dynamic analysis.";
    recommended_followup = followupFor(static_capability);
  } else {
    static_capability = "incapable_statically";
    rationale =
      "The prerequisite APIs are not imported and no runtime-resolution primitives (GetProcAddress + a library " +
      "loader) are present, so the behavior is not statically supported. Note: static analysis cannot prove a " +
      "negative under obfuscation.";
    recommended_followup = followupFor(static_capability);
  }

  return {
    behavior: behaviorKey,
    description: def.description,
    required_apis: def.apis,
    apis_present: present,
    apis_missing: missing,
    dynamic_resolution_present: dynamicResolutionPresent,
    static_capability,
    rationale,
    recommended_followup,
  };
}
