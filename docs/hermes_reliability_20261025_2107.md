# Hermes Reliability Check

Date: 2026-10-25 21:10
Setup: llama3.1:8b via Ollama (context 16384), skill soc-alert-triage v2.2
Command: hermes -t terminal,skills --skills soc-alert-triage -z "Triage the SOC alerts."
Pass = the report file was regenerated with the expected counts. Each run is a fresh Hermes process with no retries.
Reply matched = Hermes's reply contained the real counts and the real top alert (ALERT-0005).

**First-try passes: 8 of 10**

| Run | Pipeline ran | Reply matched | Seconds |
|---|---|---|---|
| 1 | PASS | yes | 28 |
| 2 | PASS | no | 14 |
| 3 | PASS | no | 13 |
| 4 | PASS | no | 14 |
| 5 | FAIL | no | 11 |
| 6 | PASS | yes | 15 |
| 7 | FAIL | no | 7 |
| 8 | PASS | yes | 14 |
| 9 | PASS | no | 15 |
| 10 | PASS | no | 23 |

Full output of each run: docs/hermes_reliability_logs/20261025_2107/
Setup note: Docker sandbox on, WSL 10 GB, tool-use enforcement on (boolean true).
