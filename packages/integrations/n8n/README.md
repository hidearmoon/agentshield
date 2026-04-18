# AgentGuard for n8n

Security check node for [n8n](https://n8n.io) — guard AI agent tool calls in workflows.

## How It Works

The AgentGuard node acts as a security gate with two outputs: **Allowed** and **Blocked**. Place it before sensitive operations in your n8n workflow.

```
[Trigger] → [AgentGuard] → Allowed → [Send Email]
                           → Blocked → [Notify Admin]
```

For AI Agent workflows, place it between the Agent node and tool nodes to intercept tool calls.

## Setup

1. Start the AgentGuard core engine.

2. Install the community node:
   ```bash
   cd ~/.n8n
   npm install n8n-nodes-agentguard
   ```

3. Restart n8n. The "AgentGuard Security Check" node appears in the node palette.

4. Add AgentGuard API credentials (Settings → Credentials → Add → AgentGuard API).

## Node Configuration

| Parameter | Description |
|-----------|-------------|
| **Tool Name** | Name of the action being checked (e.g., `send_email`) |
| **Tool Parameters** | JSON parameters for the tool call |
| **Source ID** | Data source for trust level (default: `n8n/workflow`) |
| **Agent ID** | Identifier for trace grouping (default: `n8n`) |
| **Fail Open** | Allow if AgentGuard is unreachable (default: `true`) |

## Outputs

| Output | When | Data |
|--------|------|------|
| **Allowed** (0) | Security check passed | Original item + `_agentguard.decision` |
| **Blocked** (1) | Security check failed | Original item + `_agentguard.reason` |

Both outputs include an `_agentguard` object with `decision`, `reason`, `trace_id`, and `tool_name`.
