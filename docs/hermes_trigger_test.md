# Hermes Skill Trigger Test

Model: llama3.1:8b (local, Ollama). Skill: soc-alert-triage v2.0.0 (single command).
Hermes started with: hermes -t terminal,skills (least-privilege toolsets).
Plumbing check: "echo hello" ran through the terminal tool (passed).
Skills snapshot count for the new description: ___
Prompt, identical every attempt: "Triage the SOC alerts."
Each attempt starts with /new. Pass = the report file was regenerated with the expected severity counts.

| # | Pass, first try | Pass after one follow-up | Summary matches report | Failure mode | Seconds | Notes |
|---|---|---|---|---|---|---|
| 1 | | | | | | |
| 2 | | | | | | |
| 3 | | | | | | |
| 4 | | | | | | |
| 5 | | | | | | |
| 6 | | | | | | |
| 7 | | | | | | |
| 8 | | | | | | |
| 9 | | | | | | |
| 10 | | | | | | |

Failure modes: wrong tool, wrote code, tool call printed as text, wrong command or path, skill not used, script error, other.
