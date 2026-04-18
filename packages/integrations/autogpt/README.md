# AgentGuard for AutoGPT Platform

Runtime security block for [AutoGPT Platform](https://github.com/Significant-Gravitas/AutoGPT).

## How It Works

AutoGPT Platform uses a graph-based execution engine where **Blocks** are the unit of extensibility. AgentGuard provides a security check block that can be placed before any sensitive block in a graph.

```
[User Input] → [AgentGuard Check] → allowed_data → [Sensitive Block]
                                    → blocked_reason → [Error Handler]
```

## Setup

1. Start the AgentGuard core engine.

2. Copy `agentguard_block.py` to `autogpt_platform/backend/backend/blocks/`.

3. Restart AutoGPT Platform — the block is auto-discovered.

4. In the UI, drag "AgentGuard Security Check" into your graph before sensitive blocks.

## Block Inputs/Outputs

**Inputs:**
| Field | Type | Description |
|-------|------|-------------|
| `tool_name` | string | Name of the tool/action to check |
| `tool_params` | dict | Parameters being passed to the tool |
| `api_key` | string | AgentGuard API key |
| `core_url` | string | Core engine URL (default: `http://localhost:8000`) |
| `passthrough_data` | any | Data to forward if allowed |

**Outputs:**
| Field | Type | Description |
|-------|------|-------------|
| `allowed_data` | any | Passthrough data (only on ALLOW) |
| `blocked_reason` | string | Reason (only on BLOCK) |
| `decision` | string | ALLOW / BLOCK / REQUIRE_CONFIRMATION |
| `trace_id` | string | Audit trace ID |

## Standalone Usage

The `AgentGuardChecker` class can also be used outside the Block system:

```python
from agentguard_block import AgentGuardChecker

checker = AgentGuardChecker(api_key="your-key")
result = checker.check("send_email", {"to": "user@example.com", "body": "hello"})
if result["action"] == "BLOCK":
    print(f"Blocked: {result['reason']}")
```
