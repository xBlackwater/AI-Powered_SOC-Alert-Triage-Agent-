# Hermes Reliability Check

Date: 2026-10-25 21:02
Setup: llama3.1:8b via Ollama (context 16384), skill soc-alert-triage v2.2
Command: hermes -t terminal,skills --skills soc-alert-triage -z "Triage the SOC alerts."
Pass = the report file was regenerated with the expected counts. Each run is a fresh Hermes process with no retries.
Reply matched = Hermes's reply contained the real counts and the real top alert (ALERT-0005).

**First-try passes: 10 of 10**

| Run | Pipeline ran | Reply matched | Seconds |
|---|---|---|---|
| 1 | PASS | yes | 32 |
| 2 | PASS | yes | 17 |
| 3 | PASS | yes | 15 |
| 4 | PASS | no | 14 |
| 5 | PASS | yes | 15 |
| 6 | PASS | yes | 15 |
| 7 | PASS | yes | 13 |
| 8 | PASS | yes | 15 |
| 9 | PASS | yes | 16 |
| 10 | PASS | no | 19 |

Full output of each run: docs/hermes_reliability_logs/20261025_2059/
Setup note: Docker sandbox on, WSL 10 GB, tool-use enforcement on.
Setup note correction: tool_use_enforcement was saved as the string "true"; whether Hermes applied it is unconfirmed.
