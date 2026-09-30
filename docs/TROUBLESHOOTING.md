cat > docs/TROUBLESHOOTING.md << 'EOF'
# Setup Troubleshooting Log

Real issues hit and resolved while setting up Hermes Agent + local Ollama for this project.

## Issue 1: "Ollama Cloud didn't answer" / HTTP 404 errors

**Symptom:** Hermes threw repeated 404 errors and referenced "Ollama Cloud" instead of the local model, even after entering the correct local base URL during setup.

**Root cause:** `~/.hermes/config.yaml` had `provider: "ollama-cloud"` instead of `provider: "ollama"`. The setup wizard defaulted to the cloud provider despite a local base_url being set — the two fields weren't in sync.

**Fix:**
```yaml
model:
  provider: "ollama"          # was "ollama-cloud"
  base_url: "http://localhost:11434/v1"
```

## Issue 2: Still 404ing after fixing the provider

**Symptom:** Provider now showed "Custom endpoint" (correct), but requests still failed with HTTP 404.

**Root cause:** `curl http://localhost:11434` returns a plain health-check response ("Ollama is running"), but Hermes needs the actual OpenAI-compatible chat API path, which lives at `/v1`.

**Fix:** Added `/v1` to the base_url as shown above. Confirmed working with:
```bash
curl http://localhost:11434/v1/models
```

## Issue 3: Tool call leaked as raw JSON text in chat

**Symptom:** A tool call to `web_search` appeared as literal JSON text in the response instead of being executed: {"type":"function","name":"web_search","parameters":{"query":"SOC analyst definition"}}**Root cause:** One-off formatting inconsistency from the local 8B model on the first attempt — not a configuration bug.

**Fix:** Ran `/retry`. The tool call executed correctly on the second attempt, and the agent returned a proper synthesized answer. If this recurs consistently (not just once), consider switching to a model with stronger tool-calling reliability (e.g. `qwen2.5:7b`).

## Working configuration (confirmed)

```yaml
model:
  default: "llama3.1:8b"
  provider: "ollama"
  base_url: "http://localhost:11434/v1"
```
EOF 

