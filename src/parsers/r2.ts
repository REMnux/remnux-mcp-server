/**
 * Pure parsers for radare2 JSON output (izj/izzj strings, iSj sections, aflj
 * functions, axtj cross-references) plus the marker-split for the batched
 * "Pass 2" command used by verify_string_usage.
 *
 * Every parser is defensive and NEVER throws — malformed/partial r2 output
 * returns an empty result so the classifier can degrade to `unknown` rather
 * than mistaking a parse failure for a real "no xref" answer. Field shapes were
 * captured from radare2 6.1.6; alternative key names seen across versions are
 * tolerated (e.g. function address as `addr` or `offset`).
 */

/** Self-generated markers (emitted via `?e`) that delimit the Pass-2 sections. */
export const R2_MARKERS = {
  sections: "__R2MCP_SEC__",
  functions: "__R2MCP_FNS__",
  xref: "__R2MCP_XR__",
} as const;

/** The connector caps stdout at 10MB and appends this sentinel when it does. */
const TRUNCATION_SENTINEL = "[OUTPUT TRUNCATED";

export interface R2String {
  value: string;
  vaddr: number;
  section: string;
}

export interface R2Section {
  name: string;
  vaddr: number;
  vaddrEnd: number;
  /** True when the section is executable (perm contains 'x'). */
  exec: boolean;
}

export interface R2Function {
  addr: number;
  name: string;
  size: number;
}

export interface R2Xref {
  /** Source address of the reference. */
  from: number;
  /** r2 reference type: STRN / DATA / CODE / CALL … */
  type: string;
  /** Containing function address, when r2 attributed one. */
  fcnAddr?: number;
  /** Containing function name, when present. */
  fcnName?: string;
  opcode?: string;
}

function asArray(json: string): unknown[] {
  try {
    const data = JSON.parse(json);
    return Array.isArray(data) ? data : [];
  } catch {
    return [];
  }
}

function num(v: unknown): number | undefined {
  return typeof v === "number" && Number.isFinite(v) ? v : undefined;
}

/** Parse `izj` / `izzj` string output. */
export function parseR2Strings(json: string): R2String[] {
  const out: R2String[] = [];
  for (const e of asArray(json)) {
    if (!e || typeof e !== "object") continue;
    const r = e as Record<string, unknown>;
    const value = r.string;
    const vaddr = num(r.vaddr);
    if (typeof value === "string" && vaddr !== undefined) {
      out.push({ value, vaddr, section: typeof r.section === "string" ? r.section : "" });
    }
  }
  return out;
}

/** Parse `iSj` section output into ranges with an exec flag. */
export function parseR2Sections(json: string): R2Section[] {
  const out: R2Section[] = [];
  for (const e of asArray(json)) {
    if (!e || typeof e !== "object") continue;
    const r = e as Record<string, unknown>;
    const vaddr = num(r.vaddr);
    const vsize = num(r.vsize) ?? 0;
    if (vaddr === undefined) continue;
    const perm = typeof r.perm === "string" ? r.perm : "";
    out.push({
      name: typeof r.name === "string" ? r.name : "",
      vaddr,
      vaddrEnd: vaddr + vsize,
      exec: perm.includes("x"),
    });
  }
  return out;
}

/** Parse `aflj` function list (address key is `addr` or `offset` across versions). */
export function parseR2Functions(json: string): R2Function[] {
  const out: R2Function[] = [];
  for (const e of asArray(json)) {
    if (!e || typeof e !== "object") continue;
    const r = e as Record<string, unknown>;
    const addr = num(r.addr) ?? num(r.offset);
    if (addr === undefined) continue;
    out.push({ addr, name: typeof r.name === "string" ? r.name : "", size: num(r.size) ?? 0 });
  }
  return out;
}

/** Parse `axtj` cross-reference output for one address. */
export function parseR2Xrefs(json: string): R2Xref[] {
  const out: R2Xref[] = [];
  for (const e of asArray(json)) {
    if (!e || typeof e !== "object") continue;
    const r = e as Record<string, unknown>;
    const from = num(r.from);
    if (from === undefined) continue;
    out.push({
      from,
      type: typeof r.type === "string" ? r.type : "",
      fcnAddr: num(r.fcn_addr),
      fcnName: typeof r.fcn_name === "string" ? r.fcn_name : undefined,
      opcode: typeof r.opcode === "string" ? r.opcode : undefined,
    });
  }
  return out;
}

/** Extract the radare2 version string from `?V` output (first matching line). */
export function parseR2Version(text: string): string | undefined {
  const m = text.match(/radare2\s+(\S+)/i);
  return m ? m[1] : undefined;
}

export interface SplitR2Output {
  /** True if the connector truncated the output (→ treat as incomplete). */
  truncated: boolean;
  version?: string;
  sectionsJson: string;
  functionsJson: string;
  /** Raw axtj JSON keyed by the queried address marker (hex string as emitted). */
  xrefsByVaddr: Map<string, string>;
}

/**
 * Split the batched Pass-2 stdout on the self-generated markers. The preamble
 * (before the sections marker) carries the `?V` version line; sections sit
 * between the sections and functions markers; functions between the functions
 * marker and the first xref marker; each `__R2MCP_XR__ <addr>` block holds that
 * address's axtj JSON up to the next marker or EOF.
 */
export function splitMarkedR2Output(stdout: string): SplitR2Output {
  const result: SplitR2Output = {
    truncated: stdout.includes(TRUNCATION_SENTINEL),
    sectionsJson: "",
    functionsJson: "",
    xrefsByVaddr: new Map(),
  };

  const lines = stdout.split("\n");
  type Bucket = { kind: "pre" | "sec" | "fns" | "xref"; key?: string };
  let bucket: Bucket = { kind: "pre" };
  let buf: string[] = [];

  const flush = () => {
    const text = buf.join("\n").trim();
    if (bucket.kind === "pre") {
      result.version = parseR2Version(text);
    } else if (bucket.kind === "sec") {
      result.sectionsJson = text;
    } else if (bucket.kind === "fns") {
      result.functionsJson = text;
    } else if (bucket.kind === "xref" && bucket.key) {
      result.xrefsByVaddr.set(bucket.key, text);
    }
    buf = [];
  };

  for (const line of lines) {
    const trimmed = line.trim();
    if (trimmed === R2_MARKERS.sections) {
      flush();
      bucket = { kind: "sec" };
    } else if (trimmed === R2_MARKERS.functions) {
      flush();
      bucket = { kind: "fns" };
    } else if (trimmed.startsWith(R2_MARKERS.xref + " ")) {
      flush();
      bucket = { kind: "xref", key: trimmed.slice(R2_MARKERS.xref.length + 1).trim() };
    } else {
      buf.push(line);
    }
  }
  flush();
  return result;
}
