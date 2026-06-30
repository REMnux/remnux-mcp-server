/**
 * OSINT malware-triage guidance — server-authored, bundled, offline.
 *
 * Operational tradecraft for enriching the IOCs that analyze_file / extract_iocs
 * surface (hashes, domains, IPs, URLs) against external reputation and
 * threat-intel services. It is the same category of locally-authored guidance as
 * triage-discipline.ts and the analyze_file analysis_guidance: hand-authored and
 * versioned here, with no live network fetch (the works-offline guarantee is
 * load-bearing for air-gapped REMnux deployments).
 *
 * This module returns GUIDANCE only. It never queries an external service and
 * holds no API keys — the AI runs the lookups with its own tools. The companion
 * resource catalog lives in data/osint-resources.json and is maintained by pull
 * request (see src/osint/index.ts for the loader).
 *
 * The workflow (A3) names service CATEGORIES, not specific services, so this
 * prose stays one source of truth and cannot drift from the catalog. The agent
 * resolves concrete services from the catalog via the `ioc_type` slice.
 */
export const OSINT_GUIDANCE = {
  version: "1.0.0",
  title: "OSINT malware triage — tradecraft, workflow, and a curated lookup-service catalog",
  provenance:
    "Server-authored operational guidance, bundled and offline (not synced from zeltser.com). " +
    "The resource catalog lives in data/osint-resources.json and is maintained by pull request.",
  scope:
    "Malware-analysis OSINT triage: enrich the hashes, domains, IPs, and URLs from a sample to " +
    "prioritize follow-up. This is triage, not a finished assessment or attribution. OSINT operates only on " +
    "derived indicators (hashes, domains, IPs, URLs, host artifacts); the sample itself is handled solely " +
    "inside the analysis sandbox, never executed or processed on your own host.",

  // Persistent header returned on EVERY response, not left to model discretion.
  header:
    "Leads, not verdicts. Corroborate across independent source types before trusting an indicator. " +
    "Pivots on attacker-controlled data can be poisoned. This is triage to prioritize follow-up, not a " +
    "finished assessment or attribution.",

  // A1 — OPSEC / tradecraft principles.
  tradecraft: [
    {
      title: "Hash-first, disclosure-aware",
      detail:
        "Do non-disclosing lookups before disclosing actions. Querying a SHA-256 or an IOC still transmits that " +
        "indicator to the service, and a rare or victim-specific one can reveal investigation interest, possession, " +
        "or timing even with no upload, including to an adversary who monitors a service or seeded the indicator. " +
        "It is far less exposing than uploading the sample, but it is not invisible. Uploading the sample, or " +
        "submitting an attacker URL that gets fetched, discloses content and can be visible to vendors, " +
        "subscribers, or the public. Look up the hash first, and upload only if the hash is unknown and " +
        "disclosure is authorized.",
    },
    {
      title: "Confidentiality tiering before any upload or submission",
      detail:
        "Never upload a sample or submit a URL tied to a confidential incident or an identifiable victim " +
        "to a public service without authorization. Public submissions are routinely shared with the " +
        "vendor and often searchable by others. Treat upload as irreversible disclosure.",
    },
    {
      title: "Authorization before disclosure",
      detail:
        "Uploading a sample, submitting a URL for live scanning, and actively resolving or connecting to " +
        "attacker infrastructure all require authorization tied to the engagement. This is where an AI " +
        "agent most plausibly errs, so confirm it explicitly rather than by implication.",
    },
    {
      title: "Do not tip off the adversary",
      detail:
        "Active connections to live C2 from attributable infrastructure can alert the adversary and burn " +
        "the investigation. Prefer passive sources (passive DNS, certificate transparency, existing " +
        "sandbox or urlscan results). A live URL submission fetches the attacker's infrastructure and may " +
        "be publicly visible, which makes it a disclosing action.",
    },
    {
      title: "Results are leads, not verdicts",
      detail:
        "A detection count, a sandbox family label, or a community pulse is an unverified lead to " +
        "corroborate against the local analysis and at least one independent source. A family name from " +
        "any service is resemblance, not confirmed attribution.",
    },
    {
      title: "Detection counts and source independence",
      detail:
        "A detection count is not a probability, and a low or zero count does not clear a sample (new, targeted, " +
        "or packed malware often detects low). Aggregators (CyberGordon, Pulsedive, IBM X-Force) and feeds that " +
        "re-ingest the same upstreams (the abuse.ch family, anything echoing VirusTotal) are not independent " +
        "corroboration. Three hits can be one source echoed three times, so corroborate across independent source " +
        "TYPES, and weight a forgery-resistant sample-intrinsic match (code similarity, imphash) over another " +
        "network-IOC echo.",
    },
    {
      title: "Enrichment can be poisoned",
      detail:
        "Attacker-controlled or community-sourced data (community pulses, shared hosting) can carry " +
        "planted or false-flag indicators. Corroborate across independent source TYPES, and anchor on " +
        "forgery-resistant, sample-intrinsic pivots (imphash, TLSH or ssdeep, Rich-header hash, code " +
        "similarity) which are far harder to salt than network IOCs.",
    },
    {
      title: "Validate indicators before spending lookups",
      detail:
        "Extracted IOCs include false positives, especially from managed (.NET) and Rust or Go binaries, where " +
        "type names and source filenames (for example futex.rs or System.Resources.Tools) surface as domains, " +
        "and base58 symbol names can look like wallet addresses. Benign toolchain artifacts are not IOCs either: " +
        "packer and SDK URLs such as upx.sf.net or schemas.microsoft.com appear in many unrelated binaries. " +
        "Confirm an indicator is a plausible real host or address, prefer ones the local analysis shows are " +
        "referenced by code (verify_string_usage and the extractor confidence scores), and never submit a " +
        "doubtful artifact to a third-party service.",
    },
    {
      title: "Data minimization and PII",
      detail:
        "IOCs can carry victim identifiers (internal hostnames, usernames in paths, email addresses, " +
        "tokens). Submit the minimum needed, such as a hash or a bare domain, not raw artifacts that " +
        "embed context.",
    },
    {
      title: "Record provenance",
      detail:
        "For each lookup, note the service, the exact query, the timestamp, and what it returned, so " +
        "findings are reproducible and attributable to a source.",
    },
  ],

  // A2 — Free vs paid access handling.
  access_guidance: {
    principle:
      "The server does not know whether you have paid or API-keyed access to any service, and holds no " +
      "keys. Each catalog entry carries an `access` tier.",
    rules: [
      "Default to free-first. Start with `free` and `free_account` services. Reach for `freemium` paid " +
        "features or `paid`-only services only when a free source cannot answer the question.",
      "Prefer services you can call directly without a key. Each entry also carries an `ai_access` field, and " +
        "the catalog lists `api_nokey` services first. With no keys configured, those keyless JSON APIs (for " +
        "example Shodan InternetDB, GreyNoise, ipinfo, DShield, urlscan search, crt.sh, RDAP) are what you can " +
        "use right now, and they cover most IP, domain, and URL triage passively.",
      "Never assume a key, never block on one. If a paid source would materially help, state what it " +
        "offers and let the user decide or supply access. Do not fail the triage because a paid lookup is " +
        "unavailable. Fall back to free sources and say what was not checked.",
      "The user supplies access, not the server. Any API key or paid query runs through the user's own " +
        "tools. This server never requests, stores, or transmits credentials.",
    ],
    tiers: {
      free: "No account required.",
      free_account: "Free, but registration or an API key is required.",
      freemium: "Usable free tier with paid upgrades.",
      paid: "Commercial only.",
    },
    ai_access: {
      api_nokey: "Clean JSON or REST you can call with no account. Best for an agent, and listed first.",
      api_key: "Programmatic, but needs a free or paid key or account first.",
      web: "Primarily a web UI or desktop tool, with no clean keyless API, so a browser or manual step is needed.",
    },
    // No-key reality per IOC type, so a keyless agent knows where the wall is.
    no_key_coverage: {
      note: "With no keys, keyless external pivots exist for network IOCs but are thin or absent for hash, family, and host_artifact. For family and host_artifact there is NO keyless external pivot, so stop and request an account or key (Malpedia, VirusTotal Intelligence, OTX) rather than improvising or hallucinating a lookup.",
      hash: "Team Cymru MHR only (MD5/SHA-1 via DNS, SHA-256 via HTTPS).",
      ip: "Shodan InternetDB, GreyNoise, DShield, ipinfo, RDAP, urlscan search.",
      domain: "crt.sh, RDAP, urlscan search, OpenPhish feed.",
      url: "urlscan search, OpenPhish feed.",
      family: "none keyless — request an account (Malpedia) or key.",
      host_artifact: "none keyless — request a key (VirusTotal Intelligence, OTX, ThreatFox).",
    },
    // The fastest keyless first move per IOC type, before reaching for keyed services.
    first_moves: {
      hash: "Team Cymru MHR, then stop unless you have a key.",
      ip: "Shodan InternetDB + GreyNoise + DShield + ipinfo, then RDAP for ownership.",
      domain: "crt.sh + RDAP + urlscan search of existing scans.",
      url: "urlscan search of existing scans. Do not submit attacker URLs for live scanning from your own infrastructure.",
      family: "request an account (Malpedia) to normalize the name across vendors.",
      host_artifact: "use the artifact locally (YARA, correlation); request a key for external pivots.",
    },
  },

  // Disclosure posture legend for the catalog's two disclosure fields.
  disclosure_legend: {
    query_disclosing: "Does looking something up reveal your interest? `none` means no per-indicator transmission (a bulk feed you download and grep locally, such as OpenPhish or DShield). `vendor` means the operator sees the specific indicator you queried. `public` means the query or result is searchable by anyone. Almost every live per-indicator lookup is at least `vendor`, not `none`.",
    content_disclosing: "Does using it require submitting sample or URL content that gets shared, or fetching the target live? none, vendor (shared with the operator or subscribers, or fetched from the operator's infrastructure), or public (publicly visible).",
    note: "Catalog entries report the WORST-CASE posture for the service. The caveats field explains when a lighter action (a hash lookup) is non-content-disclosing even though the query still reveals the indicator to the vendor and uploading a file is fully disclosing.",
  },

  // A3 — Workflow by artifact type and disclosure posture. Names catalog
  // CATEGORIES (in brackets), not specific services. Resolve services via the
  // `ioc_type` slice of the catalog. Ordered non-disclosing-first.
  workflow_by_ioc: {
    hash: {
      posture: "non-disclosing first",
      steps: [
        "Query [file_repo] and [multiscanner] for whether the hash is known, and [family_yara] for YARA or family hits. These are non-disclosing hash lookups.",
        "Cluster on sample-intrinsic fuzzy hashes (imphash, TLSH or ssdeep) and [code_similarity] to find related samples anchored to the binary's own properties, which are forgery-resistant and the antidote to poisoned single-source IOCs.",
        "Submit the file to a [multiscanner] or [sandbox] (content-disclosing) only if the hash is unknown and disclosure is authorized.",
      ],
    },
    url: {
      posture: "passive first",
      steps: [
        "Search existing results via [url_web], [community_intel], [passive_dns], and [cert_transparency]. These are query-disclosing at most.",
        "A live [url_web] submission is content-disclosing, so apply disclosure awareness and unlisted or private visibility, and remember it fetches the attacker's infrastructure.",
      ],
    },
    domain: {
      posture: "passive first",
      steps: [
        "Pivot passively via [passive_dns] (resolution history), [registration] (RDAP registrar and creation data), [cert_transparency], and [community_intel] to map history, ownership, and related infrastructure.",
        "Use [url_web] for current page analysis, applying the same live-submission discipline as for URLs.",
      ],
    },
    ip: {
      posture: "non-disclosing",
      steps: [
        "Use [infrastructure] enrichment for noise-versus-targeted classification, open ports and services, hostnames, and reputation.",
        "Corroborate across independent [infrastructure] and [aggregator] sources before trusting a single reputation verdict.",
      ],
    },
    family: {
      posture: "non-disclosing",
      steps: [
        "Use [family_yara] to resolve aliases across vendors, then [community_intel] to pivot from the family to its current infrastructure.",
        "Planted-pulse risk applies, so corroborate before trusting a pivot.",
      ],
    },
    host_artifact: {
      posture: "non-disclosing",
      steps: [
        "Not all host artifacts pivot equally. STRONG external pivots: a distinctive hash, certificate thumbprint, wallet or email address, or a unique mutex string. WEAK pivots: common registry paths (CurrentVersion\\Run, Explorer\\Advanced), named pipes, and service names, which are often shared across unrelated software. Pivot only on DISTINCTIVE artifacts, and note that a dynamically generated mutex has no static value to search.",
        "Search a distinctive artifact in [multiscanner], [community_intel], and [aggregator] to surface related samples and reports. Most of these searches need an account or key (for example VirusTotal Intelligence), so with no key, use the artifact for in-sandbox correlation and YARA, and ask the user for a key when an external pivot is needed. Treat any match as a lead to corroborate.",
      ],
    },
    packed: {
      posture: "content-disclosing",
      steps: [
        "If triage stalls because the sample is packed, it must be unpacked inside the analysis sandbox (REMnux) before you draw IOC conclusions, since absent strings are not absence of C2. Unpacking is a local analysis step performed with the REMnux tooling, never a command you run against the sample on your own host. A corrupted UPX header signals anti-unpack tampering that needs dynamic analysis in the sandbox. Only when in-sandbox unpacking stalls do external [unpacking] services apply, and submitting the sample to them is content-disclosing, so apply the same upload discipline. All malware handling stays inside the sandbox.",
      ],
    },
  },
} as const;
