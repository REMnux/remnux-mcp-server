/**
 * Shared known-value lists used by both noise filtering and confidence scoring.
 * Single source of truth to prevent divergence.
 */

export const PRIVATE_IP_PREFIXES = [
  "10.", "172.16.", "172.17.", "172.18.", "172.19.",
  "172.20.", "172.21.", "172.22.", "172.23.", "172.24.",
  "172.25.", "172.26.", "172.27.", "172.28.", "172.29.",
  "172.30.", "172.31.", "192.168.", "127.", "169.254.",
];

export const KNOWN_GOOD_DOMAIN_SUFFIXES = [
  "microsoft.com", "google.com", "googleapis.com", "gstatic.com",
  "w3.org", "openxmlformats.org", "xmlsoap.org", "apache.org",
  "verisign.com", "digicert.com", "globalsign.com",
  "windowsupdate.com", "windows.net", "azure.com",
  "github.com", "githubusercontent.com",
  "localhost",
  // Certificate infrastructure
  "thawte.com", "symantec.com", "entrust.net", "letsencrypt.org",
  "sectigo.com", "comodoca.com", "godaddy.com", "usertrust.com",
  // AV / security vendor domains (common in malware analysis output)
  "avast.com", "avg.com", "avira.com",
  "bitdefender.com", "kaspersky.com", "kaspersky-labs.com",
  "eset.com", "eset-la.com",
  "sophos.com", "mcafee.com", "trellix.com",
  "malwarebytes.org", "malwarebytes.com",
  "crowdstrike.com", "sentinelone.com",
  "paloaltonetworks.com", "fortinet.com", "fortiguardcenter.com",
  "trendmicro.com", "trendsecure.com",
  "f-secure.com", "f-prot.com",
  "pandasecurity.com", "emsisoft.com", "emsisoft.de",
  "webroot.com", "zonealarm.com",
  "clamav.net", "clamwin.com",
  "spybot.info", "superantispyware.com", "lavasoft.com",
  "norman.com", "quickheal.co.in", "k7computing.com",
  "drweb.com", "rising.com.cn", "ikarus.net",
  // Security community / research
  "bleepingcomputer.com", "wilderssecurity.com",
  "threatexpert.com", "virustotal.com",
  "malwareremoval.com", "geekstogo.com",
  "rootkit.com", "safer-networking.org",
];
