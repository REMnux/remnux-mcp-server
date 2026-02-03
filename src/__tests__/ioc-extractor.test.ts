/**
 * Unit tests for IOC extraction pipeline.
 *
 * Tests: extraction of standard types (IP, domain, hash, URL, email, CVE),
 * custom patterns (registry keys, Windows paths), deduplication, noise
 * filtering, confidence scoring, and edge cases.
 */

import { describe, it, expect } from "vitest";
import { extractIOCs } from "../ioc/extractor.js";
import { extractCustomPatterns } from "../ioc/patterns.js";
import { isNoise } from "../ioc/noise.js";
import { scoreIOC } from "../ioc/scoring.js";

// =========================================================================
// extractIOCs — standard types
// =========================================================================

describe("extractIOCs - standard types", () => {
  it("extracts IPv4 addresses", () => {
    const result = extractIOCs("C2 server at 8.8.8.8 and 1.2.3.4");
    const ipv4s = result.iocs.filter((e) => e.type === "ipv4");
    expect(ipv4s.map((e) => e.value)).toContain("8.8.8.8");
    expect(ipv4s.map((e) => e.value)).toContain("1.2.3.4");
  });

  it("extracts IPv6 addresses", () => {
    const result = extractIOCs("server at 2001:0db8:85a3:0000:0000:8a2e:0370:7334");
    const ipv6s = result.iocs.filter((e) => e.type === "ipv6");
    expect(ipv6s.length).toBeGreaterThanOrEqual(1);
  });

  it("extracts domains", () => {
    const result = extractIOCs("callback to evil.example.com over HTTPS");
    const domains = result.iocs.filter((e) => e.type === "domain");
    expect(domains.map((e) => e.value)).toContain("evil.example.com");
  });

  it("extracts URLs", () => {
    const result = extractIOCs("downloads from http://malware.example.com/payload.exe");
    const urls = result.iocs.filter((e) => e.type === "url");
    expect(urls.map((e) => e.value)).toContain("http://malware.example.com/payload.exe");
  });

  it("extracts email addresses", () => {
    const result = extractIOCs("contact attacker@evil.com for ransom");
    const emails = result.iocs.filter((e) => e.type === "email");
    expect(emails.map((e) => e.value)).toContain("attacker@evil.com");
  });

  it("extracts MD5 hashes", () => {
    const hash = "d41d8cd98f00b204e9800998ecf8427e";
    const result = extractIOCs(`file hash: ${hash}`);
    // This specific hash is the empty-file MD5 so it lands in noise
    const all = [...result.iocs, ...result.noise].filter((e) => e.type === "md5");
    expect(all.map((e) => e.value)).toContain(hash);
  });

  it("extracts SHA1 hashes", () => {
    const hash = "aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d";
    const result = extractIOCs(`sha1: ${hash}`);
    const sha1s = result.iocs.filter((e) => e.type === "sha1");
    expect(sha1s.map((e) => e.value)).toContain(hash);
  });

  it("extracts SHA256 hashes", () => {
    const hash = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08";
    const result = extractIOCs(`sha256: ${hash}`);
    const sha256s = result.iocs.filter((e) => e.type === "sha256");
    expect(sha256s.map((e) => e.value)).toContain(hash);
  });

  it("extracts CVE identifiers", () => {
    const result = extractIOCs("exploits CVE-2024-1234 and CVE-2023-5678");
    const cves = result.iocs.filter((e) => e.type === "cve");
    expect(cves.map((e) => e.value)).toContain("CVE-2024-1234");
    expect(cves.map((e) => e.value)).toContain("CVE-2023-5678");
  });

  it("extracts BTC addresses", () => {
    const addr = "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa";
    const result = extractIOCs(`send payment to ${addr}`);
    const btcs = result.iocs.filter((e) => e.type === "btc");
    expect(btcs.map((e) => e.value)).toContain(addr);
  });
});

// =========================================================================
// extractIOCs — custom patterns
// =========================================================================

describe("extractIOCs - custom patterns", () => {
  it("extracts registry keys (HKLM)", () => {
    const result = extractIOCs("persistence at HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run");
    const regs = result.iocs.filter((e) => e.type === "registry_key");
    expect(regs.length).toBe(1);
    expect(regs[0].value).toContain("HKLM\\Software");
  });

  it("extracts registry keys (HKCU)", () => {
    const result = extractIOCs("HKCU\\Software\\Malware\\Config set to 1");
    const regs = result.iocs.filter((e) => e.type === "registry_key");
    expect(regs.length).toBe(1);
    expect(regs[0].value).toContain("HKCU\\Software\\Malware\\Config");
  });

  it("extracts registry keys (HKEY_LOCAL_MACHINE)", () => {
    const result = extractIOCs("HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\Backdoor");
    const regs = result.iocs.filter((e) => e.type === "registry_key");
    expect(regs.length).toBe(1);
  });

  it("extracts Windows file paths", () => {
    const result = extractIOCs("drops to C:\\Users\\Public\\malware.exe");
    const paths = result.iocs.filter((e) => e.type === "windows_path");
    expect(paths.length).toBe(1);
    expect(paths[0].value).toBe("C:\\Users\\Public\\malware.exe");
  });

  it("extracts environment variable paths", () => {
    const result = extractIOCs("saved to %APPDATA%\\Malware\\config.dat");
    const paths = result.iocs.filter((e) => e.type === "windows_path");
    expect(paths.length).toBe(1);
    expect(paths[0].value).toBe("%APPDATA%\\Malware\\config.dat");
  });
});

// =========================================================================
// extractCustomPatterns — direct
// =========================================================================

describe("extractCustomPatterns", () => {
  it("returns empty array for text without patterns", () => {
    expect(extractCustomPatterns("nothing here")).toEqual([]);
  });

  it("extracts multiple registry keys", () => {
    const text = "HKLM\\A\\B and HKCU\\C\\D are both modified";
    const matches = extractCustomPatterns(text);
    expect(matches.length).toBe(2);
    expect(matches.every((m) => m.type === "registry_key")).toBe(true);
  });
});

// =========================================================================
// Deduplication
// =========================================================================

describe("deduplication", () => {
  it("deduplicates identical IOCs", () => {
    const text = "8.8.8.8 appears twice: 8.8.8.8";
    const result = extractIOCs(text);
    const ips = [...result.iocs, ...result.noise].filter((e) => e.type === "ipv4" && e.value === "8.8.8.8");
    expect(ips.length).toBe(1);
  });
});

// =========================================================================
// Noise filtering
// =========================================================================

describe("noise filtering", () => {
  it("filters private IPs to noise", () => {
    const result = extractIOCs("internal at 192.168.1.1 and 10.0.0.1");
    const noiseIps = result.noise.filter((e) => e.type === "ipv4");
    expect(noiseIps.length).toBe(2);
    expect(result.iocs.filter((e) => e.type === "ipv4").length).toBe(0);
  });

  it("filters known-good domains to noise", () => {
    const result = extractIOCs("visited google.com and microsoft.com");
    const noiseDomains = result.noise.filter((e) => e.type === "domain");
    expect(noiseDomains.map((e) => e.value)).toContain("google.com");
    expect(noiseDomains.map((e) => e.value)).toContain("microsoft.com");
  });

  it("filters empty-file hashes to noise", () => {
    const emptyMd5 = "d41d8cd98f00b204e9800998ecf8427e";
    const result = extractIOCs(`hash: ${emptyMd5}`);
    const noiseMd5 = result.noise.filter((e) => e.type === "md5");
    expect(noiseMd5.map((e) => e.value)).toContain(emptyMd5);
  });

  it("filters stock OS paths to noise", () => {
    const result = extractIOCs("imports from C:\\Windows\\System32\\ntdll.dll");
    const noisePaths = result.noise.filter((e) => e.type === "windows_path");
    expect(noisePaths.length).toBe(1);
  });
});

// =========================================================================
// isNoise — direct
// =========================================================================

describe("isNoise", () => {
  it("recognizes private IPs", () => {
    expect(isNoise("192.168.1.1", "ipv4")).toBe(true);
    expect(isNoise("10.0.0.1", "ipv4")).toBe(true);
    expect(isNoise("127.0.0.1", "ipv4")).toBe(true);
  });

  it("does not flag public IPs", () => {
    expect(isNoise("8.8.8.8", "ipv4")).toBe(false);
  });

  it("recognizes known-good domains", () => {
    expect(isNoise("google.com", "domain")).toBe(true);
    expect(isNoise("api.microsoft.com", "domain")).toBe(true);
  });

  it("does not flag unknown domains", () => {
    expect(isNoise("evil.example.com", "domain")).toBe(false);
  });

  it("recognizes all-zero hashes", () => {
    expect(isNoise("00000000000000000000000000000000", "md5")).toBe(true);
  });
});

// =========================================================================
// Confidence scoring
// =========================================================================

describe("scoreIOC", () => {
  it("scores hashes at 0.8", () => {
    expect(scoreIOC("abc123", "sha256")).toBe(0.8);
    expect(scoreIOC("abc123", "md5")).toBe(0.8);
  });

  it("scores registry keys at 0.7", () => {
    expect(scoreIOC("HKLM\\Software\\Test", "registry_key")).toBe(0.7);
  });

  it("scores all IPs at 0.5 (private IP filtering handled by noise filter)", () => {
    expect(scoreIOC("192.168.1.1", "ipv4")).toBe(0.5);
    expect(scoreIOC("8.8.8.8", "ipv4")).toBe(0.5);
  });

  it("scores public IPs at 0.5", () => {
    expect(scoreIOC("8.8.8.8", "ipv4")).toBe(0.5);
  });

  it("scores known-good domains at 0.1", () => {
    expect(scoreIOC("google.com", "domain")).toBe(0.1);
  });

  it("scores unknown domains at 0.5", () => {
    expect(scoreIOC("evil.com", "domain")).toBe(0.5);
  });

  it("scores CVEs at 0.7", () => {
    expect(scoreIOC("CVE-2024-1234", "cve")).toBe(0.7);
  });

  it("scores crypto addresses at 0.8", () => {
    expect(scoreIOC("addr", "btc")).toBe(0.8);
  });
});

// =========================================================================
// New pattern types: suspicious executables, PowerShell, ports, PDB usernames
// =========================================================================

describe("extractIOCs - suspicious executables", () => {
  it("extracts LOLBins", () => {
    const result = extractIOCs("spawns fodhelper.exe and certutil.exe");
    const exes = result.iocs.filter((e) => e.type === "suspicious_executable");
    expect(exes.map((e) => e.value)).toContain("fodhelper.exe");
    expect(exes.map((e) => e.value)).toContain("certutil.exe");
  });

  it("filters common executables (cmd.exe, powershell.exe) as noise", () => {
    expect(isNoise("cmd.exe", "suspicious_executable")).toBe(true);
    expect(isNoise("powershell.exe", "suspicious_executable")).toBe(true);
    expect(isNoise("net.exe", "suspicious_executable")).toBe(true);
    expect(isNoise("sc.exe", "suspicious_executable")).toBe(true);
  });

  it("does not filter uncommon LOLBins as noise", () => {
    expect(isNoise("fodhelper.exe", "suspicious_executable")).toBe(false);
    expect(isNoise("mimikatz.exe", "suspicious_executable")).toBe(false);
  });

  it("does not extract non-LOLBin executables", () => {
    const result = extractIOCs("runs myapp.exe");
    const exes = result.iocs.filter((e) => e.type === "suspicious_executable");
    expect(exes.length).toBe(0);
  });

  it("scores suspicious executables at 0.8", () => {
    expect(scoreIOC("mimikatz.exe", "suspicious_executable")).toBe(0.8);
  });
});

describe("extractIOCs - PowerShell cmdlets", () => {
  it("extracts known cmdlets", () => {
    const result = extractIOCs("Set-MpPreference -DisableRealtimeMonitoring $true; Invoke-Expression $payload");
    const cmdlets = result.iocs.filter((e) => e.type === "powershell_cmdlet");
    expect(cmdlets.map((e) => e.value)).toContain("Set-MpPreference");
    expect(cmdlets.map((e) => e.value)).toContain("Invoke-Expression");
  });

  it("scores PowerShell cmdlets at 0.7", () => {
    expect(scoreIOC("Invoke-Expression", "powershell_cmdlet")).toBe(0.7);
  });
});

describe("extractIOCs - network ports", () => {
  it("does not extract port from colon notation (avoids timestamp/IPv6 false positives)", () => {
    const result = extractIOCs("connects to 10.0.0.1:4444");
    const ports = result.iocs.filter((e) => e.type === "network_port");
    expect(ports.map((e) => e.value)).not.toContain("4444");
  });

  it("extracts port from 'port N' notation", () => {
    const result = extractIOCs("listening on port 20600");
    const ports = result.iocs.filter((e) => e.type === "network_port");
    expect(ports.map((e) => e.value)).toContain("20600");
  });

  it("filters common ports as noise", () => {
    expect(isNoise("80", "network_port")).toBe(true);
    expect(isNoise("443", "network_port")).toBe(true);
    expect(isNoise("22", "network_port")).toBe(true);
    expect(isNoise("53", "network_port")).toBe(true);
    expect(isNoise("8080", "network_port")).toBe(true);
    expect(isNoise("8443", "network_port")).toBe(true);
  });

  it("does not filter unusual ports", () => {
    expect(isNoise("4444", "network_port")).toBe(false);
  });

  it("scores common ports at 0.3 and unusual ports at 0.6", () => {
    expect(scoreIOC("443", "network_port")).toBe(0.3);
    expect(scoreIOC("4444", "network_port")).toBe(0.6);
  });
});

describe("extractIOCs - PDB usernames", () => {
  it("extracts username from PDB path", () => {
    const result = extractIOCs("C:\\Users\\sammi\\source\\repos\\Client\\Client.pdb");
    const users = result.iocs.filter((e) => e.type === "pdb_username");
    expect(users.map((e) => e.value)).toContain("sammi");
  });

  it("deduplicates PDB usernames", () => {
    const result = extractIOCs(
      "C:\\Users\\sammi\\repos\\A.pdb and C:\\Users\\sammi\\repos\\B.pdb"
    );
    const users = result.iocs.filter((e) => e.type === "pdb_username");
    expect(users.length).toBe(1);
  });

  it("filters generic PDB usernames as noise", () => {
    expect(isNoise("build", "pdb_username")).toBe(true);
    expect(isNoise("jenkins", "pdb_username")).toBe(true);
    expect(isNoise("admin", "pdb_username")).toBe(true);
  });

  it("does not filter real usernames", () => {
    expect(isNoise("sammi", "pdb_username")).toBe(false);
  });

  it("scores PDB usernames at 0.7", () => {
    expect(scoreIOC("sammi", "pdb_username")).toBe(0.7);
  });
});

// =========================================================================
// IOC false positive fixes
// =========================================================================

describe("IOC false positive fixes", () => {
  it("filters tool URLs (decalage.info, hexacorn.com) as noise", () => {
    expect(isNoise("https://decalage.info/oletools", "url")).toBe(true);
    expect(isNoise("https://hexacorn.com/blog", "url")).toBe(true);
  });

  it("filters short IPv6 addresses as noise", () => {
    expect(isNoise("::", "ipv6")).toBe(true);
    expect(isNoise("::C", "ipv6")).toBe(true);
    expect(isNoise("a::", "ipv6")).toBe(true);
  });

  it("does not filter valid IPv6 addresses", () => {
    expect(isNoise("2001:0db8:85a3::8a2e:0370:7334", "ipv6")).toBe(false);
  });

  it("filters short domains (< 4 chars) as noise", () => {
    expect(isNoise("j.P", "domain")).toBe(true);
    expect(isNoise("a.b", "domain")).toBe(true);
  });

  it("filters .NET namespace prefixes as domain noise", () => {
    expect(isNoise("System.Data", "domain")).toBe(true);
    expect(isNoise("System.IO", "domain")).toBe(true);
    expect(isNoise("Microsoft.Win32", "domain")).toBe(true);
  });

  it("filters MIME type fragments as domain noise", () => {
    expect(isNoise("vnd.ms", "domain")).toBe(true);
  });

  it("filters short ASN values as noise", () => {
    expect(isNoise("AS1", "asn")).toBe(true);
    expect(isNoise("AS12", "asn")).toBe(true);
  });

  it("does not filter valid ASN values", () => {
    expect(isNoise("AS13335", "asn")).toBe(false);
  });

  it("filters PE FileVersion patterns from crypto addresses", () => {
    expect(isNoise("1.0.0.0", "btc")).toBe(true);
    expect(isNoise("6.0.0.0", "eth")).toBe(true);
  });

  it("filters PE version strings as IPv4 noise (has zero octet, all small)", () => {
    expect(isNoise("1.1.0.1", "ipv4")).toBe(true);
    expect(isNoise("1.0.0.0", "ipv4")).toBe(true);
    expect(isNoise("6.0.0.0", "ipv4")).toBe(true);
  });

  it("does not filter IPs without zero octets as version strings", () => {
    expect(isNoise("6.3.5.7", "ipv4")).toBe(false);
    expect(isNoise("1.3.9.6", "ipv4")).toBe(false);
  });

  it("does not filter real public IPs as version strings", () => {
    expect(isNoise("8.8.8.8", "ipv4")).toBe(false);
    expect(isNoise("1.2.3.4", "ipv4")).toBe(false);
    expect(isNoise("45.33.32.156", "ipv4")).toBe(false);
  });

  it("filters metadata domain fragments (xmp.id)", () => {
    expect(isNoise("xmp.id", "domain")).toBe(true);
    expect(isNoise("xmp.did", "domain")).toBe(true);
  });

  it("filters file-reference domains ending in .data, .config, etc.", () => {
    expect(isNoise("CpaConfigDownList.data", "domain")).toBe(true);
    expect(isNoise("settings.config", "domain")).toBe(true);
  });

  it("filters certificate infrastructure domains", () => {
    expect(isNoise("crl.thawte.com", "domain")).toBe(true);
    expect(isNoise("ts-crl.ws.symantec.com", "domain")).toBe(true);
    expect(isNoise("ocsp.verisign.com", "domain")).toBe(true);
  });

  it("filters nsis.sf.net as tool URL noise", () => {
    expect(isNoise("http://nsis.sf.net/NSIS_Error", "url")).toBe(true);
  });

  it("filters schemas.microsoft.com URLs as noise", () => {
    expect(isNoise("http://schemas.microsoft.com/office/2006/relationships", "url")).toBe(true);
  });

  it("filters short IPv6 fragments (::Dec, ::F) as noise", () => {
    expect(isNoise("::Dec", "ipv6")).toBe(true);
    expect(isNoise("::F", "ipv6")).toBe(true);
    expect(isNoise("::c", "ipv6")).toBe(true);
  });

  it("filters invalid BTC addresses (base64 blobs) as noise", () => {
    // Random base64-like string that doesn't match BTC format
    expect(isNoise("SGVsbG9Xb3JsZEhlbGxvV29ybGRIZWxs", "btc")).toBe(true);
  });

  it("does not filter valid BTC addresses", () => {
    expect(isNoise("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa", "btc")).toBe(false);
    expect(isNoise("3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy", "btc")).toBe(false);
  });

  it("does not dual-classify hash values as crypto addresses", () => {
    // A SHA256 hash should not also appear as a BTC address
    const hash = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08";
    const result = extractIOCs(`sha256: ${hash}`);
    const btcs = [...result.iocs, ...result.noise].filter(
      (e) => e.type === "btc" && e.value === hash
    );
    expect(btcs.length).toBe(0);
  });
});

// =========================================================================
// Edge cases
// =========================================================================

describe("edge cases", () => {
  it("handles empty input", () => {
    const result = extractIOCs("");
    expect(result.iocs).toEqual([]);
    expect(result.noise).toEqual([]);
    expect(result.summary.total).toBe(0);
  });

  it("handles text with no IOCs", () => {
    const result = extractIOCs("This is just a normal sentence with no indicators.");
    expect(result.iocs.length).toBe(0);
  });

  it("summary by_type counts are correct", () => {
    const result = extractIOCs("C2 at 8.8.8.8 and 1.2.3.4, hash aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d");
    expect(result.summary.by_type["ipv4"]).toBe(2);
    expect(result.summary.by_type["sha1"]).toBe(1);
    expect(result.summary.total).toBe(result.iocs.length);
  });
});

// =========================================================================
// Real-world-ish strings output
// =========================================================================

describe("real-world strings output", () => {
  it("extracts IOCs from simulated strings output", () => {
    const stringsOutput = `
GetProcAddress
LoadLibraryA
http://evil.example.com/update.bin
HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\Backdoor
C:\\Users\\Public\\payload.dll
192.168.1.100
45.33.32.156
CVE-2021-44228
aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d
kernel32.dll
ntdll.dll
    `;

    const result = extractIOCs(stringsOutput);

    // Should find the public IP
    expect(result.iocs.some((e) => e.type === "ipv4" && e.value === "45.33.32.156")).toBe(true);
    // Private IP should be noise
    expect(result.noise.some((e) => e.type === "ipv4" && e.value === "192.168.1.100")).toBe(true);
    // Should find the URL
    expect(result.iocs.some((e) => e.type === "url")).toBe(true);
    // Should find registry key
    expect(result.iocs.some((e) => e.type === "registry_key")).toBe(true);
    // Should find the Windows path (not the stock ntdll.dll)
    expect(result.iocs.some((e) => e.type === "windows_path" && e.value.includes("payload.dll"))).toBe(true);
    // Should find CVE
    expect(result.iocs.some((e) => e.type === "cve" && e.value === "CVE-2021-44228")).toBe(true);
    // Should find SHA1
    expect(result.iocs.some((e) => e.type === "sha1")).toBe(true);
    // Summary should be non-zero
    expect(result.summary.total).toBeGreaterThan(0);
  });
});

// =========================================================================
// Vendor email filtering
// =========================================================================

describe("vendor email filtering", () => {
  it("filters @mandiant.com emails as noise", () => {
    const result = extractIOCs("Contact moritz.raabe@mandiant.com for details");
    // Check specifically for emails - domain "mandiant.com" may be extracted separately
    expect(result.iocs.find(i => i.type === "email" && i.value.includes("mandiant.com"))).toBeUndefined();
    expect(result.noise.find(i => i.type === "email" && i.value.includes("mandiant.com"))).toBeDefined();
  });

  it("filters subdomain vendor emails as noise", () => {
    const result = extractIOCs("analyst@research.crowdstrike.com");
    expect(result.iocs.find(i => i.type === "email")).toBeUndefined();
    expect(result.noise.find(i => i.type === "email")).toBeDefined();
  });

  it("does not filter non-vendor emails", () => {
    const result = extractIOCs("attacker@evil-domain.com");
    const emails = result.iocs.filter(i => i.type === "email");
    expect(emails.length).toBe(1);
  });

  it("filters @didierstevens.com tool author emails", () => {
    expect(isNoise("didier@didierstevens.com", "email")).toBe(true);
  });
});

// =========================================================================
// Private IP filtering options
// =========================================================================

describe("private IP filtering options", () => {
  it("filters private IPs by default", () => {
    const result = extractIOCs("Connected to 192.168.1.100");
    expect(result.iocs.find(i => i.value === "192.168.1.100")).toBeUndefined();
    expect(result.noise.find(i => i.value === "192.168.1.100")).toBeDefined();
  });

  it("includes private IPs when option is set", () => {
    const result = extractIOCs("Connected to 192.168.1.100", { includePrivateIPs: true });
    expect(result.iocs.find(i => i.value === "192.168.1.100")).toBeDefined();
  });

  it("includes 10.x IPs when option is set", () => {
    const result = extractIOCs("C2 at 10.0.0.50", { includePrivateIPs: true });
    expect(result.iocs.find(i => i.value === "10.0.0.50")).toBeDefined();
  });

  it("isNoise respects includePrivateIPs option", () => {
    expect(isNoise("192.168.1.1", "ipv4")).toBe(true);
    expect(isNoise("192.168.1.1", "ipv4", { includePrivateIPs: true })).toBe(false);
  });
});
