/**
 * Parser for 1768.py, Didier Stevens' Cobalt Strike beacon configuration extractor.
 *
 * 1768 exits 0 whether or not it succeeds. When it cannot process a file it says so
 * on stderr ("Error opening file ...", "Number of errors: N"), and the parser reports
 * that as tool_reported_error. "Error: ..." lines on stdout, such as "payload size too
 * large", are its probe results on a file without a beacon, not failures. A recovered
 * configuration is one line per setting, led by Cobalt Strike's own setting number,
 * followed by 1768's verdict, "Sanity check Cobalt Strike config: OK" (or NOK):
 *
 *   0x0001 payload type   0x0001 0x0002 0 windows-beacon_http-reverse_http
 *   0x0008 server,get-uri 0x0003 0x0100 '<host>,/<uri>'
 *
 * Recognition keys on the setting numbers and the verdict, which are stable across
 * releases. Setting names are display text, used only as labels.
 */

import type { ParsedToolOutput, ParseContext, Finding } from "./types.js";

/** Setting number, display name (may be empty), type, length, then the decoded value. */
const CONFIG_ENTRY = /^0x([0-9a-f]{4})\s+(.*?)\s*0x[0-9a-f]{4} 0x[0-9a-f]{4}(?:\s+(.*))?$/i;

/** Any line led by a setting number, whatever the rest of its layout. */
const SETTING_NUMBER = /^0x([0-9a-f]{4})\b/i;

/** "Sanity check <subject>: <verdict>", counted only when the subject is a Cobalt Strike config. */
const SANITY_VERDICT = /^sanity check\b([^:]*):\s*(\S+)/i;
const COBALT_STRIKE = /cobalt\s*strike/i;

/** The header 1768 prints for every file it processes. */
const FILE_HEADER = /^File:/m;

/** 1768's failure reports: "Error: ..." lines, its "Number of errors: N" tally, or a traceback. */
const ERROR_RECORDS = [/^error\b/im, /^number of errors:\s*[1-9]/im, /^Traceback \(most recent call last\):/m];

/** Payload type, port, C2 server and URI, POST URI, and license ID: the values an analyst pivots on. */
const KEY_SETTINGS = new Set(["0001", "0002", "0008", "000a", "0025"]);
const MAX_SETTING_FINDINGS = 15;
const MAX_VALUE = 200;

/** Replace anything outside printable ASCII and cap the length before quoting a value back. */
function printable(s: string): string {
  const p = s.replace(/[^ -~]/g, "?");
  return p.length > MAX_VALUE ? `${p.slice(0, MAX_VALUE)}…` : p;
}

export function parse1768Output(rawOutput: string, ctx?: ParseContext): ParsedToolOutput {
  const result: ParsedToolOutput = {
    tool: "1768",
    parsed: false,
    findings: [],
    metadata: {},
    raw: rawOutput,
  };

  // Failure records count on stderr, or in output that is not 1768's normal report (no
  // File: header, as when stderr stands in for empty stdout). On its normal stdout they are
  // probe results.
  const stderr = ctx?.stderr ?? "";
  const hasHeader = FILE_HEADER.test(rawOutput);
  const reportedError = ERROR_RECORDS.some((re) => re.test(stderr) || (!hasHeader && re.test(rawOutput)));
  if (reportedError) result.metadata.tool_reported_error = true;

  if (!hasHeader) {
    // Without the header, 1768 either failed before processing the file (and said so)
    // or printed a format this parser does not know.
    if (reportedError) result.parsed = true;
    else result.metadata.parse_error = true;
    return result;
  }
  result.parsed = true;

  let ok = 0;
  let nok = 0;
  let other = 0;
  const settingNumbers = new Set<string>();
  const settings: Finding[] = [];
  let omitted = 0;

  for (const line of rawOutput.split("\n")) {
    // Configuration lines start at column 0. Decoded profile instructions are indented.
    if (!line || /^\s/.test(line)) continue;
    const text = line.trim();
    const sanity = text.match(SANITY_VERDICT);
    if (sanity) {
      if (!COBALT_STRIKE.test(sanity[1])) continue;
      const verdict = sanity[2].toUpperCase();
      if (verdict === "OK") ok++;
      else if (verdict === "NOK") nok++;
      else other++;
      continue;
    }
    const numbered = text.match(SETTING_NUMBER);
    if (numbered && numbered[1] !== "0000") settingNumbers.add(numbered[1].toLowerCase());
    const entry = text.match(CONFIG_ENTRY);
    if (!entry || !KEY_SETTINGS.has(entry[1].toLowerCase()) || !entry[3]) continue;
    if (settings.length >= MAX_SETTING_FINDINGS) {
      omitted++;
      continue;
    }
    const id = entry[1].toLowerCase();
    const label = printable(entry[2].trim()) || "unnamed";
    settings.push({
      description: `Cobalt Strike setting ${label} (0x${id}): ${printable(entry[3])}`,
      category: "cobalt-strike-setting",
      severity: "info",
      evidence: printable(text),
    });
  }

  // One numbered line is not a configuration. A real one has dozens of settings.
  if (ok + nok + other === 0 && settingNumbers.size < 2) return result;

  const verdict = ok > 0 ? "OK" : nok > 0 ? "NOK" : "not recognized";
  result.findings.push({
    description: `Cobalt Strike beacon configuration recovered by 1768 (sanity check: ${verdict})`,
    category: "cobalt-strike-config",
    severity: ok > 0 ? "high" : nok > 0 ? "low" : "medium",
    evidence:
      `${settingNumbers.size} setting numbers, sanity verdicts ${ok} OK / ${nok} NOK / ${other} other` +
      (omitted > 0 ? `, ${omitted} more setting values not listed` : ""),
  });
  result.findings.push(...settings);
  return result;
}
