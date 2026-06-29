/**
 * Pure structured diff between two related samples (e.g. loader vs unpacked
 * payload). Operates on already-extracted metadata so it is fully unit-testable
 * with synthetic inputs; the handler does the tool runs and feeds this.
 */

export interface FileMeta {
  file: string;
  file_type: string;
  sha256: string;
  size_bytes: number;
  arch?: string;
  entropy?: number;
  compiler?: string;
  packer?: string;
  /** Imported function names. */
  imports: string[];
  import_count: number;
  /** capa capability names (empty when capa was not run). */
  capabilities: string[];
  /** Whether capa was actually run on this file (depth gate). */
  capa_run: boolean;
  /** Section names. */
  sections: string[];
}

export interface SetDiff {
  added: string[];
  removed: string[];
  common_count: number;
}

export interface FileDiff {
  file_a: { file: string; sha256: string };
  file_b: { file: string; sha256: string };
  size_delta: number;
  entropy_delta?: number;
  architecture?: { a?: string; b?: string };
  compiler?: { a?: string; b?: string };
  packer?: { a?: string; b?: string };
  imports: SetDiff;
  capabilities?: SetDiff;
  sections: SetDiff;
  notes: string[];
}

const CAP = 100;

/** Diff two string sets (case-insensitive de-dupe, original casing preserved). */
function setDiff(a: string[], b: string[]): SetDiff {
  const aSet = new Set(a.map((x) => x.toLowerCase()));
  const bSet = new Set(b.map((x) => x.toLowerCase()));
  const added = [...new Set(b)].filter((x) => !aSet.has(x.toLowerCase()));
  const removed = [...new Set(a)].filter((x) => !bSet.has(x.toLowerCase()));
  let common = 0;
  for (const x of aSet) if (bSet.has(x)) common++;
  const cap = (xs: string[]) => (xs.length > CAP ? [...xs.slice(0, CAP), `… and ${xs.length - CAP} more`] : xs);
  return { added: cap(added), removed: cap(removed), common_count: common };
}

function changed<T>(a: T | undefined, b: T | undefined): { a?: T; b?: T } | undefined {
  return a !== b ? { a, b } : undefined;
}

export function diffFileMeta(a: FileMeta, b: FileMeta): FileDiff {
  const notes: string[] = [];

  const arch = changed(a.arch, b.arch);
  if (arch) notes.push(`Architecture changed ${a.arch ?? "?"} → ${b.arch ?? "?"} — a different build/stage.`);
  const compiler = changed(a.compiler, b.compiler);
  if (compiler) notes.push(`Compiler/toolchain changed ${a.compiler ?? "?"} → ${b.compiler ?? "?"} (a toolchain mix is a strong multi-author/stage signal).`);
  const packer = changed(a.packer, b.packer);

  const imports = setDiff(a.imports, b.imports);
  const sections = setDiff(a.sections, b.sections);

  const bothCapa = a.capa_run && b.capa_run;
  const capabilities = bothCapa ? setDiff(a.capabilities, b.capabilities) : undefined;
  if (!bothCapa) notes.push("Capability (capa) diff omitted — run with depth='standard' on both files for it.");

  const entropy_delta =
    a.entropy !== undefined && b.entropy !== undefined ? Math.round((b.entropy - a.entropy) * 1000) / 1000 : undefined;
  if (packer) notes.push(`Packer differs (${a.packer ?? "none"} → ${b.packer ?? "none"}); compare on the unpacked stages for a meaningful import/capability diff.`);

  return {
    file_a: { file: a.file, sha256: a.sha256 },
    file_b: { file: b.file, sha256: b.sha256 },
    size_delta: b.size_bytes - a.size_bytes,
    ...(entropy_delta !== undefined ? { entropy_delta } : {}),
    ...(arch ? { architecture: arch } : {}),
    ...(compiler ? { compiler } : {}),
    ...(packer ? { packer } : {}),
    imports,
    ...(capabilities ? { capabilities } : {}),
    sections,
    notes,
  };
}
