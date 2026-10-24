#!/usr/bin/env bash
# hermes_triage.sh - single entry point for the Hermes skill.
# Runs deterministic triage (no LLM) and prints the top of the report.
# Usage: hermes_triage.sh [alerts.json]
# Fresh mode: if ~/.soc_triage_fresh exists and no file is given, a new labeled
# batch is generated for each run (labels stripped before triage).
set -euo pipefail
SCRIPTS="$(cd "$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")" && pwd)"
SKILL="$(dirname "$SCRIPTS")"
REPO="$(cd "$SKILL/../../.." && pwd)"
REPORT="$REPO/docs/hermes_triage_report.md"
# Hermes may put its own Python first on PATH; fall back to the system one.
PY=python3
"$PY" -c "import requests" 2>/dev/null || PY=/usr/bin/python3

if [ -z "${1:-}" ] && [ -f "$HOME/.soc_triage_fresh" ]; then
  BATCHES="$REPO/batches"
  mkdir -p "$BATCHES"
  SEED=$(( $(date +%s) % 1000000 ))
  ( cd "$BATCHES" && "$PY" "$SKILL/examples/generate_labeled_alerts.py" 60 "$SEED" > /dev/null )
  mv "$BATCHES/sample_alerts_labeled.json" "$BATCHES/batch_${SEED}_labeled.json"
  "$PY" - "$BATCHES/batch_${SEED}_labeled.json" "$BATCHES/latest.json" << 'PYEOF'
import json, sys
alerts = json.load(open(sys.argv[1]))
for a in alerts:
    a.pop("ground_truth", None)
    a.pop("scenario", None)
json.dump(alerts, open(sys.argv[2], "w"), indent=2)
PYEOF
  ALERTS="$BATCHES/latest.json"
  NOTE="Alert batch: new for this run (seed $SEED, 60 alerts)"
else
  ALERTS="${1:-$SKILL/examples/demo_alerts.json}"
  NOTE="Alert batch: $(basename "$ALERTS")"
fi

"$PY" "$SCRIPTS/triage.py" "$ALERTS" --no-llm --out "$REPORT" > /dev/null
echo "Report written to $REPORT"
echo "$NOTE"
echo
head -20 "$REPORT"
