#!/usr/bin/env bash
# hermes_reliability.sh - run the soc-alert-triage skill through Hermes N times
# and record whether the pipeline actually ran (report regenerated with expected counts).
# Usage: hermes_reliability.sh [runs]
set -uo pipefail
RUNS="${1:-10}"
REPO="$HOME/AI-Powered_SOC-Alert-Triage-Agent-"
REPORT="$REPO/docs/hermes_triage_report.md"
EXPECTED="Severity counts: Critical: 18, High: 3, Medium: 10, Low: 29"
PROMPT="Triage the SOC alerts."
STAMP="$(date +%Y%m%d_%H%M)"
LOGDIR="$REPO/docs/hermes_reliability_logs/$STAMP"
OUT="$REPO/docs/hermes_reliability_$STAMP.md"
mkdir -p "$LOGDIR"

rows=""
passes=0
for i in $(seq 1 "$RUNS"); do
  rm -f "$REPORT"
  start=$(date +%s)
  timeout 300 hermes -t terminal,skills --skills soc-alert-triage -z "$PROMPT" > "$LOGDIR/run_$i.txt" 2>&1
  secs=$(( $(date +%s) - start ))
  if grep -qF "$EXPECTED" "$REPORT" 2>/dev/null; then
    ran=PASS; passes=$((passes + 1))
  else
    ran=FAIL
  fi
  if grep -qF "Critical: 18" "$LOGDIR/run_$i.txt" && grep -qF "ALERT-0005" "$LOGDIR/run_$i.txt"; then
    reply=yes
  else
    reply=no
  fi
  rows+="| $i | $ran | $reply | $secs |"$'\n'
  echo "Run $i: $ran (reply matched: $reply, ${secs}s)"
done

{
  echo "# Hermes Reliability Check"
  echo
  echo "Date: $(date '+%Y-%m-%d %H:%M')"
  echo "Setup: llama3.1:8b via Ollama (context 16384), skill soc-alert-triage v2.2"
  echo "Command: hermes -t terminal,skills --skills soc-alert-triage -z \"$PROMPT\""
  echo "Pass = the report file was regenerated with the expected counts. Each run is a fresh Hermes process with no retries."
  echo "Reply matched = Hermes's reply contained the real counts and the real top alert (ALERT-0005)."
  echo
  echo "**First-try passes: $passes of $RUNS**"
  echo
  echo "| Run | Pipeline ran | Reply matched | Seconds |"
  echo "|---|---|---|---|"
  printf '%s' "$rows"
  echo
  echo "Full output of each run: docs/hermes_reliability_logs/$STAMP/"
} > "$OUT"
echo
echo "Passed $passes of $RUNS. Results: $OUT"
