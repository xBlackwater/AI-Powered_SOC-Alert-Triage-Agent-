# Discord Integration

Status: working as of October 24, 2026. The Hermes gateway runs a Discord bot, "SOC Triage Agent". Its terminal commands run inside the Docker sandbox (see docs/sandbox.md).

## Setup
- Bot created in the Discord Developer Portal with Public Bot off and the Message Content and Server Members intents on.
- `hermes gateway setup` stored the bot token in ~/.hermes/.env (not in this repo) and allowlisted only the owner's Discord user ID.
- Bot tools limited to terminal and skills: `platform_toolsets.discord: [terminal, skills]`.
- Mid-turn messages hidden: `display.platforms.discord.interim_assistant_messages: false`.
- The private #soc-triage channel is a free-response channel with a channel prompt that carries the triage instructions (`discord.free_response_channels`, `discord.channel_prompts`).

## How to use
1. In #soc-triage, send /reset.
2. Send: Triage the SOC alerts.
3. Wait 3-4 minutes. Verify the run was real by matching the bot's counts against the report: grep "Severity counts" docs/hermes_triage_report.md

## Fresh alert batches
- `fresh-on` turns on fresh mode. Each run generates a new 60-alert batch with a new seed. Labels are stripped before triage, and labeled copies are kept in batches/ (gitignored).
- `fresh-off` returns to the fixed 60-alert demo set. Turn fresh mode off before running the reliability script, which expects 18/3/10/29.
- `fresh-status` shows the current setting. The switch is the file .fresh_mode in the project folder (gitignored), so the sandbox can see it.
- Tested October 24, 2026: new batches used only already-cached IPs and hashes and ran in about 1-2 seconds.

## Findings
- The skill did not appear as a Discord slash command. Typing /soc-alert-triage as a DM message loaded it, but results were unreliable: 1 correct answer in 5 attempts.
- Failures included a fake "out-of-band user message" reply, an off-topic reply, a fabricated alert list after running the real command, and a tool call printed as text instead of executed.
- DMs keep conversation history. Fabricated alerts from one attempt were repeated in a later reply until /reset was used.
- With the triage instructions attached to the channel, both tests so far (one before the sandbox, one after) returned counts that matched the report. Reliability has not been measured systematically.
