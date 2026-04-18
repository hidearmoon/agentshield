# AgentGuard MCP Guard

Runtime security for [MCP (Model Context Protocol)](https://modelcontextprotocol.io) servers.

## Two Integration Patterns

### Pattern 1: Decorator (recommended for new servers)

Wrap individual tool handlers. One line per tool:

```python
from mcp.server import Server
from agentguard_mcp import MCPShield

app = Server("my-server")
shield = MCPShield(api_key="your-key")

@app.tool()
@shield.guard
async def query_database(query: str) -> str:
    """Execute a database query."""
    return db.execute(query)

@app.tool()
@shield.guard
async def send_email(to: str, body: str) -> str:
    """Send an email."""
    return mailer.send(to, body)
```

### Pattern 2: Proxy (zero changes to existing servers)

Sit between the MCP client and your existing server:

```bash
# Instead of:
#   claude --mcp "python -m my_server"
# Run through the proxy:
agentguard-mcp-proxy --upstream "python -m my_server" --api-key "your-key"
```

```python
from agentguard_mcp import MCPShieldProxy
import asyncio

proxy = MCPShieldProxy(
    upstream_command=["python", "-m", "my_mcp_server"],
    agentguard_url="http://localhost:8000",
    api_key="your-key",
)
asyncio.run(proxy.run_stdio())
```

The proxy intercepts every `tools/call` JSON-RPC message, checks it against AgentGuard, and either forwards to the upstream server or returns a blocked error.

## Configuration

| Parameter | Default | Description |
|-----------|---------|-------------|
| `api_key` | (required) | AgentGuard API key |
| `base_url` | `http://localhost:8000` | AgentGuard core engine URL |
| `agent_id` | `mcp-server` | Agent identifier for traces |
| `timeout` | `10.0` | Request timeout in seconds |
| `fail_open` | `True` | Allow tool calls if AgentGuard is unreachable |

## How Decisions Map to MCP

| AgentGuard Decision | MCP Behavior |
|---------------------|--------------|
| ALLOW | Tool call proceeds normally |
| BLOCK | JSON-RPC error response with reason |
| REQUIRE_CONFIRMATION | Blocked with descriptive message (MCP has no built-in confirmation UI) |
