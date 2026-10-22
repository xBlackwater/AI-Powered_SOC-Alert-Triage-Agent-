# Hermes Reliability Check

Date: 2026-10-22 14:57
Setup: llama3.1:8b via Ollama (context 16384), skill soc-alert-triage v2.2
Command: hermes -t terminal,skills --skills soc-alert-triage -z "Triage the SOC alerts."
Pass = the report file was regenerated with the expected counts. Each run is a fresh Hermes process with no retries.
Reply matched = Hermes's reply contained the real counts and the real top alert (ALERT-0005).

**First-try passes: 8 of 10**

| Run | Pipeline ran | Reply matched | Seconds |
|---|---|---|---|
| 1 | PASS | no | 210 |
| 2 | PASS | yes | 1128 |
| 3 | PASS | yes | 123 |
| 4 | PASS | yes | 114 |
| 5 | PASS | yes | 114 |
| 6 | PASS | yes | 113 |
| 7 | PASS | yes | 138 |
| 8 | PASS | yes | 110 |
| 9 | FAIL | no | 127 |
| 10 | FAIL | no | 93 |

Full output of each run: docs/hermes_reliability_logs/20261022_1419/
