# AgentShield for Dify

Runtime security for [Dify](https://github.com/langgenius/dify) — intercepts all tool calls in agent and workflow modes.

## How It Works

Dify routes every tool execution through a single chokepoint: `ToolEngine._invoke()`. This integration patches that method to run AgentShield security checks before each tool executes. This covers all tool types: builtin tools, API tools, plugin tools, MCP tools, and workflow-as-tool.

## Setup

1. Start the AgentShield core engine:
   ```bash
   docker compose -f docker/docker-compose.yml up -d
   ```

2. Copy `agentshield_dify.py` into your Dify installation.

3. Add to Dify's startup (e.g., in `app.py`):
   ```python
   from agentshield_dify import install
   install(api_key="your-agentshield-key", core_url="http://localhost:8000")
   ```

That's it. All tool calls in all agents and workflows are now guarded.

## Configuration

| Parameter | Default | Description |
|-----------|---------|-------------|
| `api_key` | (required) | AgentShield API key |
| `core_url` | `http://localhost:8000` | AgentShield core engine URL |
| `agent_id` | `dify` | Agent identifier for traces |
| `fail_open` | `True` | Allow tool calls if AgentShield is unreachable |
| `timeout` | `10.0` | Request timeout in seconds |

## Behavior

| Decision | Dify Behavior |
|----------|--------------|
| ALLOW | Tool executes normally |
| BLOCK | Returns `[Security] Tool call blocked: {reason}` message |
| REQUIRE_CONFIRMATION | Returns `[Security] Confirmation required: {reason}` message |
