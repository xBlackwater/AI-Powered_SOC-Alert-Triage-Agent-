mkdir -p docs
cat > docs/PLAN.md << 'EOF'
# Capstone Project Plan: AI-Powered SOC Alert Triage Agent

## 1. Project Summary

**Goal:** Build a Hermes Agent skill that automates SOC alert triage — ingesting raw security alerts, enriching them with threat intelligence, scoring severity, mapping to MITRE ATT&CK, and producing a ranked, human-readable investigation queue.

**Scope boundary:** Read-only / advisory. The agent enriches and recommends — it does not take containment actions (no host isolation, no account disabling, no firewall changes).

## 2. Architecture

Alert Source (CSV/JSON) → Hermes Agent Core (Ollama local model)
→ IOC Extraction → Enrichment (VirusTotal, AbuseIPDB, WHOIS) → ATT&CK Mapping
→ Severity Scoring + Justification → Ranked Triage Report


**Stack (confirmed $0 cost):**
- Agent framework: Hermes Agent (self-hosted, MIT-licensed)
- LLM engine: Ollama running Llama 3.1 8B or Qwen 3 14B locally
- Sandbox: Docker (Hermes's built-in isolation)
- Enrichment APIs (free tiers): VirusTotal (~500 lookups/day), AbuseIPDB (1,000/day), public WHOIS
- Dataset: CICIDS2017 (public, labeled) or a synthetic alert generator

## 3. The Hermes Skill

skills/cybersecurity/soc-alert-triage/
├── SKILL.md
├── scripts/
│ ├── extract_iocs.py
│ ├── enrich_vt.py
│ ├── enrich_abuseipdb.py
│ ├── score_severity.py
│ └── mitre_lookup.py
└── examples/
└── sample_alerts.json


**Workflow the skill follows:**
1. Ingest alert (timestamp, src/dest IP, alert type, raw log)
2. Extract IOCs (IPs, hashes, domains, URLs)
3. Selectively enrich — agent decides which lookups matter, not a fixed pipeline
4. Map to MITRE ATT&CK technique where possible
5. Score severity with a written justification
6. Output ranked report

## 4. Timeline (12 weeks)

| Week | Milestone |
|------|-----------|
| 1–2  | Environment setup: Hermes + Ollama + API keys working |
| 3    | Dataset ready, IOC extraction working |
| 4–5  | Enrichment scripts built and wired in |
| 6    | Agent decision logic for selective enrichment |
| 7    | Severity scoring + justification generation |
| 8    | MITRE ATT&CK mapping |
| 9    | Report output (markdown/Slack) |
| 10   | Full evaluation run against labeled dataset |
| 11   | Write-up: architecture, evaluation, risk/governance |
| 12   | Polish + demo rehearsal |

## 5. Evaluation Plan

- Precision/recall of severity classification vs. ground-truth labels
- Time-to-triage vs. manual review baseline
- Enrichment efficiency: lookups skipped by agent judgment vs. naive "enrich everything" baseline
- Qualitative review of generated justifications

## 6. Risk & Governance

- Read-only/advisory only — no auto-remediation
- Docker isolation for all agent execution
- Human-in-the-loop for all response decisions
- Alert/log content treated as untrusted input (prompt injection awareness)
- API keys via environment variables, never hardcoded

## 7. Stretch Goals

- Natural-language query layer over triaged alerts
- Multi-agent split (network logs / host logs / phishing sub-agents)
- Contribute the finished skill back to the open-source Hermes SOC-triage proposal
