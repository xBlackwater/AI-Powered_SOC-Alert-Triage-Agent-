# SOC Alert Triage & Enrichment

## When to use this skill
Use this skill when the user asks you to triage, enrich, investigate, or assess security alerts — whether from a file (e.g. `sample_alerts.json`), pasted alert text, or a description of suspicious activity. Trigger phrases include: "triage these alerts," "check this IP/hash," "investigate this alert," or "what's the severity of this."

## What this skill does
You act as a first-pass SOC analyst. For each alert, you:
1. Read the alert and identify any indicators of compromise (IOCs) in it — IP addresses and file hashes are the two types this skill currently supports.
2. Decide which IOCs are actually worth enriching. Skip obviously internal/private IPs (10.x.x.x, 192.168.x.x, 172.16-31.x.x) unless the user specifically asks — enrichment APIs are for external threat intel, not internal network topology.
3. Enrich each external IOC using the scripts below.
4. Combine the enrichment results into a severity assessment with a clear, human-readable justification.
5. If triaging multiple alerts, present them ranked from most to least urgent.

## Available enrichment tools

### IP reputation check (AbuseIPDB)
Run this for any external source or destination IP in an alert:

python3 skills/cybersecurity/soc-alert-triage/scripts/check_ip.py <ip_address>

Returns an abuse confidence score (0-100%), country, ISP, and total report count. A score above 25% is generally worth flagging; above 75% is a strong signal of malicious activity.

### File hash reputation check (VirusTotal)
Run this for any file hash present in an alert (MD5 or SHA-256):

python3 skills/cybersecurity/soc-alert-triage/scripts/check_hash.py <file_hash>

Returns detection counts across security vendors (malicious/suspicious/undetected/harmless). Any nonzero "malicious" count is significant; double-digit detections indicate high-confidence malware.

## Severity scoring guidance

Combine enrichment results into one of these levels, and always explain *why* in one or two sentences:

- **Critical**: Hash flagged malicious by 10+ vendors, OR IP abuse score above 75%, OR both an enriched IP and hash point the same direction.
- **High**: Hash flagged by 1-9 vendors, OR IP abuse score 25-75%.
- **Medium**: No malicious enrichment hits, but the alert type itself is inherently higher-risk (e.g. "Privilege Escalation Attempt," "Known C2 Beacon Pattern").
- **Low**: Clean enrichment results (0% abuse score, 0 malicious hash detections) and a routine alert type (e.g. isolated failed login).

## Example justification format

> **ALERT-0007 — Severity: High**
> Source IP 45.155.205.233 shows a 68% abuse confidence score on AbuseIPDB with 340 prior reports, no ISP whitelist status. Alert type "Known C2 Beacon Pattern" combined with this external reputation data suggests likely command-and-control communication. Recommend escalation for manual investigation.

## Notes
- Both scripts require API keys set as environment variables (`ABUSEIPDB_API_KEY`, `VT_API_KEY`) — already configured on this system.
- This skill is advisory only. Never take containment or remediation action (no host isolation, no blocking, no account changes) — always present findings for human review.

## Exact steps to follow — do not skip or substitute

1. Use your `read_file` tool to read the alerts JSON file at the exact path the user gave you.
2. Parse the JSON to get the list of alerts.
3. For each alert, look at its `src_ip`, `dest_ip`, and `file_hash` fields (if present).
4. Skip any IP starting with `10.`, `192.168.`, or `172.16.` through `172.31.` — these are internal/private.
5. For each remaining external IP, use your `terminal` tool to run exactly this command, substituting the real IP:
   `python3 skills/cybersecurity/soc-alert-triage/scripts/check_ip.py <ip_address>`
6. For each file hash present, use your `terminal` tool to run exactly this command, substituting the real hash:
   `python3 skills/cybersecurity/soc-alert-triage/scripts/check_hash.py <file_hash>`
7. Do NOT invent a tool called "triage" or any other tool name — only use `read_file` and `terminal` as described above.
8. After running all checks, summarize each alert's severity using the scoring guidance below.
