# Getting Started

## Step 0: Check your machine
- 16GB RAM recommended, ~15GB free disk space
- Windows: install WSL2 first (`wsl --install` in admin PowerShell, then restart, then open the Ubuntu app)
- Mac/Linux: use your normal Terminal

## Step 1: Install Ollama

curl -fsSL https://ollama.com/install.sh | sh
ollama --version
ollama pull llama3.1:8b
ollama run llama3.1:8b


## Step 2: Install Hermes Agent

git clone https://github.com/NousResearch/hermes-agent.git
cd hermes-agent

Follow the repo's README to install, then point it at your local Ollama instance (usually via a `.env` or config file — set the model provider/base URL to `http://localhost:11434`).

## Step 3: Get free API keys
- VirusTotal: https://www.virustotal.com → profile → API Key
- AbuseIPDB: https://www.abuseipdb.com → Account → API

Store as environment variables (add to `~/.bashrc`):

export VT_API_KEY="your_key_here"
export ABUSEIPDB_API_KEY="your_key_here"


## Step 4: Get alert data
- Download CICIDS2017 (https://www.unb.ca/cic/datasets/ids-2017.html), or
- Use a synthetic alert generator script for full control during early development

## Step 5: Standalone enrichment script
Write and test a small script that checks one IP against AbuseIPDB before wiring anything into Hermes — isolates API/auth issues from agent issues.

## Step 6: Wire it into Hermes
Connect the working script as a Hermes tool/skill, following the structure in `docs/PLAN.md`. Get one enrichment type fully working end-to-end before adding more.

## Troubleshooting
- Ollama slow/won't run: try a smaller model or check free RAM
- Hermes can't reach Ollama: make sure `ollama serve` is running in a separate terminal
- API key errors: confirm the env var was exported in the *same* terminal session you're running scripts from
