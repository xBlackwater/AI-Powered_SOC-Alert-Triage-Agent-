# Discord Integration

Status: working as of October 24, 2026. The Hermes gateway runs a Discord bot, "SOC Triage Agent".

## Setup
- Bot created in the Discord Developer Portal with Public Bot off and the Message Content and Server Members intents on.
- `hermes gateway setup` stored the bot token in ~/.hermes/.env (not in this repo) and allowlisted only the owner's Discord user ID.
- Bot tools limited to terminal and skills: `platform_toolsets.discord: [terminal, skills]`.
- Mid-turn messages hidden: `display.platforms.discord.interim_assistant_messages: false`.
- The private #soc-triage channel is a free-response channel with a channel prompt that carries the triage instructions (`discord.free_response_channels`, `discord.channel_prompts`).

## How to use
1. In #soc-triage, send /reset.
2. Send: Triage the SOC alerts.
3. Wait 3-4 minutes. Verify the run was real: grep "Severity counts" docs/hermes_triage_report.md

## Findings
- The skill did not appear as a Discord slash command. Typing /soc-alert-triage as a DM message loaded it, but results were unreliable: 1 correct answer in 5 attempts.
- Failures included a fake "out-of-band user message" reply, an off-topic reply, a fabricated alert list after running the real command, and a tool call printed as text instead of executed.
- DMs keep conversation history. Fabricated alerts from one attempt were repeated in a later reply until /reset was used.
- With the triage instructions attached to the channel, the first test returned the correct counts and top alerts.
- Reliability of the channel setup has been tested on one run only.

