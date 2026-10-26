# Hermes Reliability Check

Date: 2026-10-25 20:54
Setup: llama3.1:8b via Ollama (context 16384), skill soc-alert-triage v2.2
Command: hermes -t terminal,skills --skills soc-alert-triage -z "Triage the SOC alerts."
Pass = the report file was regenerated with the expected counts. Each run is a fresh Hermes process with no retries.
Reply matched = Hermes's reply contained the real counts and the real top alert (ALERT-0005).

**First-try passes: 10 of 10**

| Run | Pipeline ran | Reply matched | Seconds |
|---|---|---|---|
| 1 | PASS | no | 46 |
| 2 | PASS | no | 13 |
| 3 | PASS | yes | 22 |
| 4 | PASS | yes | 15 |
| 5 | PASS | yes | 16 |
| 6 | PASS | yes | 16 |
| 7 | PASS | yes | 16 |
| 8 | PASS | no | 12 |
| 9 | PASS | yes | 15 |
| 10 | PASS | yes | 14 |

Full output of each run: docs/hermes_reliability_logs/20261025_2051/
Setup note: Docker sandbox on, WSL 10 GB, tool-use enforcement off (default).
