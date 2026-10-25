# Docker Sandbox

Status: working as of October 24, 2026. Hermes runs every terminal command the agent issues (CLI and Discord) inside a Docker container instead of directly on the host.

## Setup
- Docker Engine installed in WSL (`docker.io`); the user is in the `docker` group.
- Image `soc-triage-sandbox` built from docker/Dockerfile: Python 3.11-slim plus requirements.txt, running as a non-root user that matches the host user ID.
- Hermes settings in ~/.hermes/config.yaml (outside this repo):
  - terminal.backend: docker
  - terminal.docker_image: soc-triage-sandbox
  - terminal.docker_run_as_host_user: true
  - terminal.docker_volumes: the project folder (same path as on the host) and ~/soc-triage.sh (read-only)
  - terminal.docker_extra_args: --network=none
  - No API keys or tokens are forwarded into the container.
- ~/soc-triage.sh is a small launcher that calls the project's hermes_triage.sh by absolute path, so it works both on the host and in the sandbox.
- Hermes adds its own hardening: all Linux capabilities dropped, no-new-privileges, and a process limit.
- Rebuild the image: docker build -t soc-triage-sandbox -f docker/Dockerfile --build-arg UID=$(id -u) --build-arg GID=$(id -g) .
- Switch back to running commands directly on the host: hermes config set terminal.backend local

## Checks (October 24, 2026), run inside the container Hermes uses
| Check | Result |
|---|---|
| Network mode | none |
| Capabilities | all dropped; no-new-privileges set |
| User | blackwater (not root) |
| Home folder contents | project folder, launcher, and default shell files only |
| ~/.hermes (bot token and config) | not present |
| API keys or tokens in environment | 0 (nonzero on the host) |
| Internet access | blocked (name resolution fails) |
| Writing reports to the project folder | works |

Before the sandbox, the agent's commands ran with the user's full access, including ~/.hermes/.env (the Discord bot token) and the API keys in the shell environment.

## Limits
- The project folder is mounted read-write, so a bad command could still change or delete project files. Git history is the recovery path.
- Enrichment lookups that are not already cached fail inside the sandbox, because it has no network and no API keys. The demo set and fresh batches use only cached indicators.
- Hermes itself runs on the host and controls Docker, and membership in the docker group is close to administrator access on this machine. The sandbox protects against the agent's commands, not against Hermes or the user.

## Memory
WSL memory was raised from about 7.4 GB to 10 GB (C:\Users\<user>\.wslconfig: memory=11GB, swap=4GB). Before the change, the model, Hermes, and Docker together left 277 MB available and nearly filled swap.
