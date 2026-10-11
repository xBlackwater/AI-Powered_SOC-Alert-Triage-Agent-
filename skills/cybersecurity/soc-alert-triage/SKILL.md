---
name: soc-alert-triage
description: "Triage SOC security alerts. Runs the triage pipeline (threat-intel enrichment, severity scoring, MITRE ATT&CK mapping) and summarizes the ranked report."
version: 2.2.0
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

## Step 1: run the triage script

Make exactly one call to the terminal tool, with exactly these arguments:

{"command": "bash ~/soc-triage.sh"}

The command must be exactly: bash ~/soc-triage.sh
- Do not add a file path or any other arguments. The script already knows which alerts file to use.
- Never use the word "terminal" as the command. "terminal" is the name of the tool, not something to run.

## Step 2: report the results

The command prints the top of a ranked triage report. Reply to the user with:
- the "Severity counts" line, copied exactly
- the top 5 rows of the table: alert ID, type, triaged severity, and ATT&CK ID

## Rules

- Do not write code or create files.
- Do not read the alerts file yourself. The script does the enrichment and scoring.
- Use only what the command printed. Do not add severities, IPs, or techniques.
- If the command prints an error, show the error and stop. Do not guess at the cause.
- This tool is advisory only. Never recommend blocking, isolating, or other containment.
