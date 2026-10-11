---
name: soc-alert-triage
description: "Triage SOC security alerts. Runs the triage pipeline (threat-intel enrichment, severity scoring, MITRE ATT&CK mapping) and summarizes the ranked report."
version: 2.0.0
author: xBlackwater
license: MIT
platforms: [linux]
metadata:
  hermes:
    tags: [security, soc, triage, alerts, threat-intel, mitre-attack]
    homepage: https://github.com/xBlackwater/AI-Powered_SOC-Alert-Triage-Agent-
---

# SOC Alert Triage

Use this skill whenever the user asks to triage, prioritize, rank, or assess security alerts.

## Do exactly this

1. Call the `terminal` tool once, in the foreground, with this exact command:
   `bash ~/soc-triage.sh`
   If the user named a specific alerts file, add its full path after the command:
   `bash ~/soc-triage.sh /full/path/to/alerts.json`
2. The command prints the top of a ranked triage report. Reply to the user with:
   - the "Severity counts" line, copied exactly
   - the top 5 rows of the table: alert ID, type, triaged severity, and ATT&CK ID

## Rules

- Do not write code, create files, or call any tool other than `terminal`.
- Do not read the alerts file yourself. The script does the enrichment and scoring.
- Use only what the command printed. Do not add severities, IPs, or techniques.
- If the command prints an error, show the error and stop. Do not try another approach.
- This tool is advisory only. Never recommend blocking, isolating, or other containment.
