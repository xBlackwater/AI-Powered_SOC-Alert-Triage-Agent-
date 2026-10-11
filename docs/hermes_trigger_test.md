# Hermes Integration: Test Log (October 10-11, 2026)

Model: llama3.1:8b (local, Ollama). Hermes started with: hermes -t terminal,skills.
Pass = Hermes actually ran the pipeline, confirmed by the report file being regenerated with
the expected counts (Critical: 18, High: 3, Medium: 10, Low: 29). Hermes's reply alone was never trusted.

## Before fixes: natural-language prompt, skill v2.0.0, Ollama default context

| # | Prompt | Result | What the model did |
|---|---|---|---|
| 1 | Triage the SOC Alerts. | Fail | Never loaded the skill; printed fake tool calls as text (invented "logstash" and "splunk" tools). /retry wrote a Python function instead of acting. |
| 2 | Triage the SOC alerts. | Fail | Called a nonexistent tool "soc_triage"; Hermes rejected it. |
| 3 | Triage the SOC security alerts. | Fail | Searched tools instead of skills; printed fake read_file/terminal calls and made up their output (fake requirements.txt, fake git log). |
| 4 | Triage the SOC security alerts. | Fail | Called nonexistent "soc_triage_security_alerts", claimed to load a fake skill (v1.1.1), and printed a fabricated triage report for alerts that do not exist. |

Also failed before the fixes: "/soc-alert-triage Triage the SOC alerts." and "Use the terminal tool to run: bash ~/soc-triage.sh" (the model wrote a tutorial instead of calling the tool).

## Fixes applied
1. Raised Ollama's context window to 16,384 tokens (OLLAMA_CONTEXT_LENGTH in a systemd override at /etc/systemd/system/ollama.service.d/context.conf).
2. Invoked the skill explicitly with /soc-alert-triage instead of relying on the model to find it.
3. SKILL.md v2.1: gave the exact tool arguments, {"command": "bash ~/soc-triage.sh"}.
4. SKILL.md v2.2: removed the optional file-path form.

## After fixes

| Run | Prompt | Result |
|---|---|---|
| Bare command | bash ~/soc-triage.sh | Pass |
| Skill v2.0 | /soc-alert-triage Triage the SOC alerts. | Fail: loaded the skill and called the terminal tool, but ran the word "terminal" as the command (exit 127) |
| Skill v2.1 | /soc-alert-triage Triage the SOC alerts. | Fail: ran the right script but added an invented file path (file not found) |
| Skill v2.2, first try | /soc-alert-triage Triage the SOC alerts. | Fail (details not recorded) |
| Skill v2.2, after /retry | same | Pass: ran bash ~/soc-triage.sh and reported the correct counts and top 5 alerts with ATT&CK IDs |

## Not yet established
- First-try reliability of the final setup: one success so far, and it needed a retry.
- Whether the context increase or the explicit invocation mattered more, because both changed together.
