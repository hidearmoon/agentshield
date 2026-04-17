# AgentShield for n8n

Security check node for [n8n](https://n8n.io) — guard AI agent tool calls in workflows.

## How It Works

The AgentShield node acts as a security gate with two outputs: **Allowed** and **Blocked**. Place it before sensitive operations in your n8n workflow.

```
[Trigger] → [AgentShield] → Allowed → [Send Email]
                           → Blocked → [Notify Admin]
```

For AI Agent workflows, place it between the Agent node and tool nodes to intercept tool calls.

## Setup

1. Start the AgentShield core engine.

2. Install the community node:
   ```bash
   cd ~/.n8n
   npm install n8n-nodes-agentshield
   ```

3. Restart n8n. The "AgentShield Security Check" node appears in the node palette.

4. Add AgentShield API credentials (Settings → Credentials → Add → AgentShield API).

## Node Configuration

| Parameter | Description |
|-----------|-------------|
| **Tool Name** | Name of the action being checked (e.g., `send_email`) |
| **Tool Parameters** | JSON parameters for the tool call |
| **Source ID** | Data source for trust level (default: `n8n/workflow`) |
| **Agent ID** | Identifier for trace grouping (default: `n8n`) |
| **Fail Open** | Allow if AgentShield is unreachable (default: `true`) |

## Outputs

| Output | When | Data |
|--------|------|------|
| **Allowed** (0) | Security check passed | Original item + `_agentshield.decision` |
| **Blocked** (1) | Security check failed | Original item + `_agentshield.reason` |

Both outputs include an `_agentshield` object with `decision`, `reason`, `trace_id`, and `tool_name`.
