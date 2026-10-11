#!/usr/bin/env bash
# hermes_triage.sh - single entry point for the Hermes skill.
# Runs deterministic triage (no LLM) and prints the top of the report.
# Usage: hermes_triage.sh [alerts.json]
set -euo pipefail
SCRIPTS="$(cd "$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")" && pwd)"
SKILL="$(dirname "$SCRIPTS")"
REPO="$(cd "$SKILL/../../.." && pwd)"
ALERTS="${1:-$SKILL/examples/demo_alerts.json}"
REPORT="$REPO/docs/hermes_triage_report.md"
# Hermes may put its own Python first on PATH; fall back to the system one.
PY=python3
"$PY" -c "import requests" 2>/dev/null || PY=/usr/bin/python3
"$PY" "$SCRIPTS/triage.py" "$ALERTS" --no-llm --out "$REPORT" > /dev/null
echo "Report written to $REPORT"
echo
head -20 "$REPORT"
