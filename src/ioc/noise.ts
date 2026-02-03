/**
 * Known-good filtering for IOC extraction.
 * Filters out private IPs, common benign domains, empty hashes, and stock OS paths.
 */

import { PRIVATE_IP_PREFIXES, KNOWN_GOOD_DOMAIN_SUFFIXES, VENDOR_EMAIL_DOMAINS } from "./known-values.js";

/** Tool/library URLs that appear in analysis tool output, not from the sample. */
const TOOL_URL_DOMAINS = new Set([
  "decalage.info",
  "hexacorn.com",
  "blog.didierstevens.com",
  "didierstevens.com",
  "github.com",
  "remnux.org",
  "virustotal.com",
  "hybrid-analysis.com",
  "nsis.sf.net",
  "sf.net",
]);

/** .NET namespace prefixes that are not IOCs. */
const DOTNET_NAMESPACE_PREFIXES = [
  "System.", "Microsoft.", "Windows.", "Internal.", "Interop.",
  "MS.", "mscorlib.", "netstandard.",
];

/** MIME type fragments that match domain patterns but are not domains. */
const MIME_FRAGMENTS = new Set([
  "vnd.ms", "vnd.openxmlformats", "vnd.oasis",
]);

const EMPTY_HASHES = new Set([
  // MD5 of empty
  "d41d8cd98f00b204e9800998ecf8427e",
  // SHA1 of empty
  "da39a3ee5e6b4b0d3255bfef95601890afd80709",
  // SHA256 of empty
  "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
  // All zeros
  "00000000000000000000000000000000",
  "0000000000000000000000000000000000000000",
  "0000000000000000000000000000000000000000000000000000000000000000",
]);

/** Case-insensitive set for stock Windows paths. */
const STOCK_PATHS = new Set([
  "c:\\windows\\system32\\ntdll.dll",
  "c:\\windows\\system32\\kernel32.dll",
  "c:\\windows\\system32\\advapi32.dll",
  "c:\\windows\\system32\\user32.dll",
  "c:\\windows\\system32\\gdi32.dll",
  "c:\\windows\\system32\\msvcrt.dll",
]);

/** Domains that are metadata fragments or file references, not real IOCs. */
const METADATA_DOMAIN_NOISE = new Set([
  "xmp.id", "xmp.did", "xmp.iid",
]);

/** REMnux tool script filenames that look like domains (e.g., "numbers-to-string.py"). */
const TOOL_SCRIPT_NAMES = new Set([
  "numbers-to-string.py", "re-search.py", "base64dump.py",
  "translate.py", "file-magic.py", "xorsearch.py",
  "oledump.py", "rtfdump.py", "zipdump.py", "pdfid.py",
  "pdf-parser.py", "emldump.py", "dotnetfile_dump.py",
]);

/**
 * File extensions misidentified as TLDs when URL path components are extracted as domains.
 * E.g., "debug.zip", "payload.dll", "config.json".
 */
const FILE_EXTENSION_RE = /\.(zip|rar|7z|tar|gz|bz2|xz|exe|dll|sys|drv|bat|cmd|ps1|vbs|js|jar|apk|deb|rpm|msi|cab|iso|img|bin|dat|tmp|bak|log|txt|csv|json|xml|html|htm|pdf|doc|docx|xls|xlsx|ppt|pptx)$/i;

/**
 * IPv4 addresses that look like PE version strings.
 * E.g., 1.1.0.1, 1.0.0.0, 6.0.0.0 — common in ProductVersion / FileVersion fields.
 * Conservative heuristic: all octets ≤ 20 AND at least one octet is 0.
 * Note: versions without a zero octet (e.g., 6.3.5.7) are NOT caught — acceptable trade-off.
 */
function isLikelyVersionString(ip: string): boolean {
  const parts = ip.split(".");
  if (parts.length !== 4) return false;
  const nums = parts.map((p) => parseInt(p, 10));
  return nums.every((n) => n >= 0 && n <= 20) && nums.some((n) => n === 0);
}

/** Options for noise filtering */
export interface NoiseFilterOptions {
  /** Include private/internal IP addresses (default: false) */
  includePrivateIPs?: boolean;
}

export function isNoise(value: string, type: string, options?: NoiseFilterOptions): boolean {
  if (type === "ipv4") {
    // Skip private IP filtering if option is set
    if (!options?.includePrivateIPs && PRIVATE_IP_PREFIXES.some((p) => value.startsWith(p))) return true;
    // Filter PE version strings like 1.0.0.0, 1.1.0.1 (must contain a zero octet)
    if (isLikelyVersionString(value)) return true;
    return false;
  }

  if (type === "ipv6") {
    // Reject short IPv6 fragments like "::", "::C", "::Dec", "::F" — need at least 6 hex chars
    if (value.replace(/:/g, "").length < 6) return true;
    return false;
  }

  if (type === "domain") {
    const lower = value.toLowerCase();
    // Reject domains shorter than 4 chars (e.g., "j.Ph", "32.be")
    if (lower.length < 4) return true;
    // Reject .NET namespace fragments (case-insensitive)
    if (DOTNET_NAMESPACE_PREFIXES.some((p) => lower.startsWith(p.toLowerCase()))) return true;
    // Reject MIME type fragments
    if (MIME_FRAGMENTS.has(lower)) return true;
    // Reject known metadata fragments (xmp.id, etc.)
    if (METADATA_DOMAIN_NOISE.has(lower)) return true;
    // Reject REMnux tool script filenames (e.g., "numbers-to-string.py")
    if (TOOL_SCRIPT_NAMES.has(lower)) return true;
    // Reject any "domain" that looks like a script filename (e.g., "deobfuscator.py")
    if (/\.(py|pl|rb|sh|ps1)$/i.test(lower)) return true;
    // Reject file-like "domains" — URL path components misidentified as domains
    if (FILE_EXTENSION_RE.test(lower)) return true;
    // Reject single-label "domains" that look like file references (e.g., "CpaConfigDownList.data")
    // These have no subdomain depth and end in a data-like TLD
    const parts = lower.split(".");
    if (parts.length === 2 && /^(data|config|local|internal|tmp|log|bak|old)$/.test(parts[1])) return true;
    return KNOWN_GOOD_DOMAIN_SUFFIXES.some(
      (suffix) => lower === suffix || lower.endsWith("." + suffix),
    );
  }

  if (type === "url") {
    try {
      const hostname = new URL(value).hostname.toLowerCase();
      // Filter tool URLs
      if (TOOL_URL_DOMAINS.has(hostname) ||
          [...TOOL_URL_DOMAINS].some((d) => hostname.endsWith("." + d))) {
        return true;
      }
      return KNOWN_GOOD_DOMAIN_SUFFIXES.some(
        (suffix) => hostname === suffix || hostname.endsWith("." + suffix),
      );
    } catch {
      return false;
    }
  }

  if (type === "md5" || type === "sha1" || type === "sha256" || type === "sha512") {
    return EMPTY_HASHES.has(value.toLowerCase());
  }

  if (type === "suspicious_executable") {
    const lower = value.toLowerCase();
    return ["cmd.exe", "powershell.exe", "net.exe", "sc.exe"].includes(lower);
  }

  if (type === "windows_path") {
    return STOCK_PATHS.has(value.toLowerCase());
  }

  if (type === "network_port") {
    const port = parseInt(value, 10);
    return [80, 443, 22, 53, 8080, 8443].includes(port);
  }

  if (type === "pdb_username") {
    const lower = value.toLowerCase();
    return ["build", "jenkins", "admin", "user", "default", "administrator"].includes(lower);
  }

  if (type === "asn") {
    // Require AS + at least 4 digits (e.g., AS1234)
    if (!/^AS\d{4,}$/i.test(value)) return true;
    return false;
  }

  if (type === "btc") {
    // Filter PE FileVersion patterns
    if (/^\d+\.\d+\.\d+\.\d+$/.test(value)) return true;
    // Validate BTC address format: P2PKH (1...), P2SH (3...), or Bech32 (bc1...)
    // P2PKH/P2SH: Base58Check, 25-34 chars starting with 1 or 3
    // Bech32: starts with bc1, 42-62 chars
    if (/^[13][a-km-zA-HJ-NP-Z1-9]{24,33}$/.test(value)) return false;
    if (/^bc1[ac-hj-np-z02-9]{25,59}$/.test(value)) return false;
    // Doesn't match valid BTC format — likely a base64 blob or hash fragment
    return true;
  }

  if (type === "eth" || type === "xmr") {
    // Filter PE FileVersion patterns
    if (/^\d+\.\d+\.\d+\.\d+$/.test(value)) return true;
    return false;
  }

  // Filter security vendor emails (tool authors, not malware IOCs)
  if (type === "email") {
    const emailDomain = value.split("@")[1]?.toLowerCase();
    if (emailDomain && VENDOR_EMAIL_DOMAINS.some(d =>
      emailDomain === d || emailDomain.endsWith("." + d)
    )) {
      return true;
    }
    return false;
  }

  return false;
}
