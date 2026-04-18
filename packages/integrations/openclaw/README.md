# AgentGuard Plugin for OpenClaw

Runtime security layer for [OpenClaw](https://openclaw.ai) — inspects every tool call before execution.

## How It Works

The plugin registers three hooks in OpenClaw's agent loop:

| Hook | Purpose | Latency Impact |
|------|---------|---------------|
| `before_tool_call` | Check tool call against security policy → ALLOW / BLOCK / CONFIRM | μs–ms (Layer 1-2), ms–2s (Layer 3, rare) |
| `before_prompt_build` | Inject trust-level markers into system prompt | None (string append) |
| `after_tool_call` | Record tool results into audit trail | Async, non-blocking |

## Setup

1. Start the AgentGuard core engine:
   ```bash
   docker compose -f docker/docker-compose.yml up -d
   ```

2. Copy this plugin to your OpenClaw plugins directory.

3. Configure in `openclaw.json`:
   ```json
   {
     "plugins": {
       "enabled": ["agentguard"],
       "entries": {
         "agentguard": {
           "config": {
             "coreUrl": "http://localhost:8000",
             "apiKey": "your-agentguard-api-key"
           }
         }
       }
     }
   }
   ```

## Trust Level Mapping

OpenClaw channels are automatically mapped to AgentGuard trust levels:

| Channel | Trust Level | Rationale |
|---------|-------------|-----------|
| Direct CLI / API | VERIFIED | Authenticated user input |
| Slack, Teams | INTERNAL | Internal team communication |
| WhatsApp, Telegram, Discord, Signal | EXTERNAL | External messaging |
| Email, Web | EXTERNAL | External data sources |
| System | TRUSTED | System-generated |

Customize via the `trustMapping` config option.

## Fail-Open Design

If the AgentGuard core engine is unreachable, the plugin **allows** the tool call to proceed and logs a warning. Security checks are additive — they should never break your agent when the security service is temporarily unavailable.
