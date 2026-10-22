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
## Notes on runs 1, 2, 9, and 10 (from the saved output)

- Run 1: The pipeline ran, but Hermes's final reply contained no results. It returned text formatted like a Hermes "out-of-band user message" marker, followed by a paraphrase of the skill's own instructions.
- Run 2: Took 1,128 seconds. The 300-second timeout did not stop it, because timeout only sends a stop request. The median run took about 2 minutes.
- Run 9: The model printed the tool call as text ({"command": "bash ~/soc-triage.sh"}) instead of making it, so nothing ran. It then fabricated a complete report: wrong counts (Critical 2, High 5, Medium 10, Low 15), alerts that do not exist, and ATT&CK IDs including "T877.001", which is not a valid technique ID.
- Run 10: The model printed the tool call as text and stopped. Nothing ran, and no report was claimed.

Summary: the pipeline ran in 8 of 10 runs. The result was correct end to end (pipeline ran and the reply matched the report) in 7 of 10. One run returned a fabricated report, which only the report-file check exposed.
