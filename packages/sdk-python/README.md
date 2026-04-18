# AgentGuard Python SDK

Lightweight security guardrails for AI agents. All security logic runs server-side.

## Quick Start

```python
from agentguard import Shield

shield = Shield()  # reads AGENTGUARD_API_KEY from env

@shield.guard
async def send_email(to: str, body: str) -> str:
    ...  # your tool implementation

# The server decides: ALLOW, BLOCK, or REQUIRE_CONFIRMATION
await send_email(to="user@company.com", body="Hello")
```

## Session Mode

```python
async with shield.session("Summarize my emails") as s:
    result = await s.guarded_executor.execute(
        "read_inbox", {"limit": 10}, read_inbox_fn
    )
```

## Error Handling

```python
from agentguard import Shield, ToolCallBlocked, ConfirmationRejected, ServerError

shield = Shield()

@shield.guard
async def send_email(to: str, body: str) -> str:
    ...

try:
    await send_email(to="user@test.com", body="hi")
except ToolCallBlocked as e:
    print(f"Blocked: {e.reason} (trace: {e.trace_id})")
except ConfirmationRejected:
    print("User declined confirmation")
except ServerError as e:
    print(f"Server error: {e}")
```

## Configuration

```python
# Explicit configuration
shield = Shield(
    api_key="your-key",
    base_url="https://shield.yourcompany.com",
    timeout=10.0,
    max_retries=3,
    agent_id="my-agent",
)
```

Or via environment variables:
- `AGENTGUARD_API_KEY` (required)
- `AGENTGUARD_BASE_URL` (default: http://localhost:8000)
- `AGENTGUARD_TIMEOUT` (default: 10.0)
- `AGENTGUARD_AGENT_ID`

Or via `agentguard.yaml` in the working directory.

## Data Sanitization

```python
# Sanitize external data before processing
result = await shield.sanitize(
    data=email_body,
    source="email/external",
)
# result.content has hidden injections removed
# result.trust_level shows the computed trust level
```

## Framework Integrations

```python
from agentguard.integrations import LangChainShield, CrewAIShield

# LangChain
guarded = LangChainShield(shield).wrap(agent_executor)

# CrewAI
guarded = CrewAIShield(shield).wrap(crew)

# AutoGen
from agentguard.integrations import AutoGenShield
AutoGenShield(shield).wrap(assistant)

# Claude Agent SDK
from agentguard.integrations import ClaudeAgentGuard
guarded_handler = ClaudeAgentGuard(shield).wrap(my_tool_handler)
```
