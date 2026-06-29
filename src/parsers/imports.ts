/**
 * Parser for a PE import table from `readpe -i -f json` (pev suite).
 *
 * Produces a structured, queryable view of which APIs a PE statically imports.
 * This is the enabling primitive for check_behavior_prerequisites: knowing the
 * import surface lets us ask "can this binary even call the APIs a behavior
 * requires?" — without conflating "the API is imported" with "the behavior
 * runs".
 *
 * Note on what imports prove: a statically imported API means the binary *can*
 * call it; it is not evidence the call happens on a reachable path. Absence is
 * weaker still — APIs can be resolved at runtime (GetProcAddress + LoadLibrary)
 * or hidden by packing.
 */

export interface PeImports {
  /** True when readpe produced valid JSON we could read (even if zero imports). */
  parsed: boolean;
  dlls: Array<{ dll: string; functions: string[] }>;
  /** Lowercased imported function names, for case-insensitive lookup. */
  functionSet: Set<string>;
  /** Total number of imported functions across all DLLs. */
  count: number;
}

function emptyImports(parsed: boolean): PeImports {
  return { parsed, dlls: [], functionSet: new Set(), count: 0 };
}

export function parsePeImports(readpeJson: string): PeImports {
  let data: unknown;
  try {
    data = JSON.parse(readpeJson);
  } catch {
    return emptyImports(false);
  }
  if (!data || typeof data !== "object") return emptyImports(false);

  const imported = (data as Record<string, unknown>)["Imported functions"];
  // Valid JSON but no import table (e.g. a PE with no imports) → parsed, empty.
  if (!Array.isArray(imported)) return emptyImports(true);

  const dlls: Array<{ dll: string; functions: string[] }> = [];
  const functionSet = new Set<string>();
  let count = 0;

  for (const lib of imported) {
    if (!lib || typeof lib !== "object") continue;
    const l = lib as Record<string, unknown>;
    const dll = typeof l.Name === "string" ? l.Name : "";
    const fns = Array.isArray(l.Functions) ? l.Functions : [];
    const names: string[] = [];
    for (const fn of fns) {
      if (!fn || typeof fn !== "object") continue;
      const name = (fn as Record<string, unknown>).Name;
      if (typeof name === "string" && name.length > 0) {
        names.push(name);
        functionSet.add(name.toLowerCase());
        count++;
      }
    }
    dlls.push({ dll, functions: names });
  }

  return { parsed: true, dlls, functionSet, count };
}

/**
 * Whether a required API (given as a base name without the ANSI/Unicode suffix)
 * is present in the import set. Matches the base plus its `...A` / `...W`
 * variants — e.g. required "InternetOpenUrl" is satisfied by "InternetOpenUrlW".
 * We APPEND candidate suffixes rather than stripping, because many genuine API
 * names already end in 'a'/'w' (e.g. "GetClipboardData", "ShowWindow").
 */
export function apiPresent(requiredBaseName: string, functionSet: Set<string>): boolean {
  const base = requiredBaseName.toLowerCase();
  return functionSet.has(base) || functionSet.has(base + "a") || functionSet.has(base + "w");
}
