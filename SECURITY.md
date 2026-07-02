# Security policy

## Supported versions

We ship security fixes only in the latest release of [@remnux/mcp-server](https://www.npmjs.com/package/@remnux/mcp-server). Update with `npm install -g @remnux/mcp-server@latest`, or run `remnux install` on a REMnux system to pull the current version.

## Reporting a vulnerability

Report exploitable vulnerabilities privately through this repository's "[Report a vulnerability](https://github.com/REMnux/remnux-mcp-server/security/advisories/new)" form on GitHub. GitHub opens a private draft advisory that only you and the maintainers can see. We use the draft to confirm the behavior and coordinate a fix.

For security topics that do not put users at risk, open a regular [issue](https://github.com/REMnux/remnux-mcp-server/issues). Hardening ideas, false positives in the blocked-command patterns, and documentation gaps are good candidates.

## Scope

Container and VM isolation is the security boundary for this server. The server exists to run analysis commands inside a disposable REMnux system, so command execution there is intended behavior. The [Security Model](README.md#security-model) section of the README describes the threat model in detail.

We treat a report as in scope when it demonstrates one of the following:

- Bypassing authentication on the HTTP transport, such as reaching MCP tools on a token-protected or loopback-bound server without the token
- Reading or writing files on the analyst's workstation beyond the documented behavior of `upload_from_host` and `download_file`, including escapes from the `--sandbox` and `--ingest-root` confinement
- Executing commands outside the REMnux container or VM, such as on the analyst's workstation
- Breaking out of the quoting that the SSH connector applies to remote commands

We treat the following as intended behavior:

- Arbitrary command execution by `run_tool` inside the REMnux container or VM, including pipes, `sudo`, and interpreters
- The absence of shell-metacharacter filtering and command allowlists, a deliberate choice the README explains
- Any exposure that requires the `--insecure-no-auth` opt-out
- Prompt injection carried in malware samples that manipulates the AI client, which the README documents as a known limitation
- Resource exhaustion inside the disposable analysis environment

## What to expect

We review private reports and respond through the draft advisory thread. When we fix a reported issue, we ship the fix in a new npm release. We credit the reporter in the fix commit, the release notes, or an advisory.
