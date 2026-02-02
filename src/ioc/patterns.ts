/**
 * Custom regex patterns for IOC types not covered by ioc-extractor.
 * Covers registry keys and Windows file paths common in malware analysis.
 */

export interface PatternMatch {
  value: string;
  type: string;
}

// Trailing-punctuation chars that are likely sentence terminators, not part of the IOC
const TRAIL_CLEAN_RE = /[.)}\]]+$/;

const REGISTRY_KEY_RE =
  /\b(HK(?:LM|CU|CR|U|CC|EY_LOCAL_MACHINE|EY_CURRENT_USER|EY_CLASSES_ROOT|EY_USERS|EY_CURRENT_CONFIG)\\[^\s"',;|&<>]+)/gi;

const WINDOWS_PATH_RE =
  /\b([A-Z]:\\(?:[^\s"',;|&<>]+\\)*[^\s"',;|&<>]+)/gi;

const ENV_PATH_RE =
  /(%[A-Z_]+%\\[^\s"',;|&<>]+)/gi;

/** Well-known LOLBins and suspicious executables seen in malware. */
const LOLBINS = new Set([
  "fodhelper.exe", "mshta.exe", "regsvr32.exe", "rundll32.exe",
  "certutil.exe", "bitsadmin.exe", "msiexec.exe", "wscript.exe",
  "cscript.exe", "wmic.exe", "schtasks.exe", "sc.exe",
  "net.exe", "net1.exe", "netsh.exe", "attrib.exe",
  "icacls.exe", "bcdedit.exe", "vssadmin.exe",
  "cmd.exe", "powershell.exe", "pwsh.exe",
  "mimikatz.exe", "psexec.exe", "procdump.exe",
]);
const SUSPICIOUS_EXE_RE =
  /\b([a-zA-Z0-9_\-]+\.exe)\b/gi;

/** PowerShell cmdlets commonly abused by malware. */
const POWERSHELL_CMDLET_RE =
  /\b(Invoke-Expression|Invoke-WebRequest|Invoke-Mimikatz|Invoke-Command|Start-Process|New-Object|Set-MpPreference|Add-MpPreference|Disable-WindowsOptionalFeature|Set-ExecutionPolicy|ConvertTo-SecureString|Import-Module|Get-WmiObject|Invoke-WmiMethod|New-Service|Set-ItemProperty|Get-Process|Stop-Process|Remove-Item|Get-Credential|IEX|IWR|ICM)\b/g;

/** Network port patterns: "port 4444", ":4444", etc. */
const NETWORK_PORT_RE =
  /\bport\s+(\d{1,5})\b/gi;

/** PDB paths that reveal developer usernames. */
const PDB_USERNAME_RE =
  /[A-Z]:\\Users\\([^\\]+)\\.*\.pdb/gi;

/** Strip trailing sentence punctuation that regex over-captures. */
function cleanTrailing(value: string): string {
  return value.replace(TRAIL_CLEAN_RE, "");
}

export function extractCustomPatterns(text: string): PatternMatch[] {
  const results: PatternMatch[] = [];

  for (const m of text.matchAll(REGISTRY_KEY_RE)) {
    results.push({ value: cleanTrailing(m[1]), type: "registry_key" });
  }

  for (const m of text.matchAll(WINDOWS_PATH_RE)) {
    results.push({ value: cleanTrailing(m[1]), type: "windows_path" });
  }

  for (const m of text.matchAll(ENV_PATH_RE)) {
    results.push({ value: cleanTrailing(m[1]), type: "windows_path" });
  }

  // Suspicious executables (LOLBins + known attack tools)
  for (const m of text.matchAll(SUSPICIOUS_EXE_RE)) {
    if (LOLBINS.has(m[1].toLowerCase())) {
      results.push({ value: m[1].toLowerCase(), type: "suspicious_executable" });
    }
  }

  // PowerShell cmdlets
  for (const m of text.matchAll(POWERSHELL_CMDLET_RE)) {
    results.push({ value: m[1], type: "powershell_cmdlet" });
  }

  // Network ports
  for (const m of text.matchAll(NETWORK_PORT_RE)) {
    const port = parseInt(m[1], 10);
    if (port > 0 && port <= 65535) {
      results.push({ value: String(port), type: "network_port" });
    }
  }

  // PDB path usernames
  for (const m of text.matchAll(PDB_USERNAME_RE)) {
    results.push({ value: m[1], type: "pdb_username" });
  }

  return results;
}
