# AI-Powered SOC Alert Triage Agent

An autonomous AI agent that automates the initial triage and enrichment stage of the SOC alert lifecycle — built on [Hermes Agent](https://github.com/NousResearch/hermes-agent), running entirely on free, open-source tooling.

## Problem

SOC analysts are overwhelmed by alert volume, most of which is false positives. Manually enriching every alert with threat intel context and prioritizing it takes time analysts often don't have. This project automates that first-pass triage step — enriching, scoring, and explaining alerts — while keeping a human analyst in charge of any actual response.

## What it does

1. Ingests raw security alerts (JSON/CSV)
2. Extracts indicators of compromise (IPs, hashes, domains, URLs)
3. Selectively enriches IOCs using threat intel APIs (the agent decides which lookups are worth running, not a fixed pipeline)
4. Maps alert behavior to MITRE ATT&CK techniques
5. Generates a severity score with a written justification
6. Outputs a ranked triage report

**Scope note:** this agent is read-only/advisory. It does not take containment or remediation actions — no host isolation, no account changes. It recommends; a human decides.

## Tech stack

| Component | Tool |
|---|---|
| Agent framework | [Hermes Agent](https://github.com/NousResearch/hermes-agent) (MIT-licensed) |
| LLM inference | [Ollama](https://ollama.com), local model (Llama 3.1 8B) |
| Threat intel | VirusTotal (free tier), AbuseIPDB (free tier), public WHOIS |
| Sandboxing | Docker (Hermes's built-in isolation) |
| Dataset | [CICIDS2017](https://www.unb.ca/cic/datasets/ids-2017.html) + synthetic alert generator |

Everything above runs at $0 cost — see `docs/PLAN.md` for the full cost breakdown.

## Project structure

.
├── docs/ # proposal, plan, notes
├── skills/cybersecurity/soc-alert-triage/
│ ├── SKILL.md # Hermes skill definition
│ ├── scripts/ # extraction, enrichment, scoring scripts
│ └── examples/ # sample alerts
├── data/ # datasets (gitignored — see below)
└── README.md

## Setup

1. Install [Ollama](https://ollama.com) and pull a model: `ollama pull llama3.1:8b`
2. Clone and install [Hermes Agent](https://github.com/NousResearch/hermes-agent), pointing it at your local Ollama instance
3. Get free API keys from [VirusTotal](https://www.virustotal.com) and [AbuseIPDB](https://www.abuseipdb.com)
4. Store keys as environment variables (never commit them — see `.gitignore`)

Full step-by-step walkthrough: `docs/GETTING_STARTED.md`

## Status

🚧 In progress — capstone project, [current semester/year].

## Documentation

- [`docs/capstone_project_proposal.md`](docs/capstone_project_proposal.md) — submitted project proposal
- [`docs/PLAN.md`](docs/PLAN.md) — architecture, timeline, evaluation plan

## Author

xBlackwater — Cybersecurity Capstone Project

## License

MIT
