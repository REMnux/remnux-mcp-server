/**
 * Simple confidence scoring for extracted IOCs.
 * Higher scores indicate more specificity / likely malicious relevance.
 */

import { PRIVATE_IP_PREFIXES, KNOWN_GOOD_DOMAIN_SUFFIXES } from "./known-values.js";

export function scoreIOC(value: string, type: string): number {
  switch (type) {
    case "md5":
    case "sha1":
    case "sha256":
    case "sha512":
    case "ssdeep":
      return 0.8;

    case "url":
      // URLs with paths are more specific
      try {
        const u = new URL(value.startsWith("http") ? value : `http://${value}`);
        return u.pathname.length > 1 ? 0.6 : 0.4;
      } catch {
        return 0.5;
      }

    case "domain": {
      const lower = value.toLowerCase();
      if (KNOWN_GOOD_DOMAIN_SUFFIXES.some((s) => lower === s || lower.endsWith("." + s))) {
        return 0.1;
      }
      return 0.5;
    }

    case "ipv4": {
      if (PRIVATE_IP_PREFIXES.some((p) => value.startsWith(p))) {
        return 0.2;
      }
      return 0.5;
    }

    case "ipv6":
      return 0.5;

    case "email":
      return 0.4;

    case "cve":
      return 0.7;

    case "registry_key":
      return 0.7;

    case "windows_path":
      return 0.5;

    case "suspicious_executable":
      return 0.8;

    case "powershell_cmdlet":
      return 0.7;

    case "network_port": {
      const port = parseInt(value, 10);
      if ([80, 443, 22, 53, 8080, 8443].includes(port)) return 0.3;
      return 0.6;
    }

    case "pdb_username":
      return 0.7;

    case "btc":
    case "eth":
    case "xmr":
      return 0.8;

    case "asn":
    case "mac":
      return 0.4;

    default:
      return 0.5;
  }
}
