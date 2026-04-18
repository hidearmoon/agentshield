"""
AgentGuard MCP Guard — two integration patterns for MCP servers.

Pattern 1: Decorator (@shield.guard)
    Wrap individual MCP tool handlers. Minimal code change.

Pattern 2: Proxy server (MCPShieldProxy)
    Sit between MCP client and MCP server. Zero code change to existing servers.

Usage (decorator pattern):

    from mcp.server import Server
    from agentguard_mcp import MCPShield

    app = Server("my-server")
    shield = MCPShield(api_key="your-key")

    @app.tool()
    @shield.guard
    async def query_database(query: str) -> str:
        return db.execute(query)

Usage (proxy pattern):

    from agentguard_mcp import MCPShieldProxy

    proxy = MCPShieldProxy(
        upstream_command=["python", "-m", "my_mcp_server"],
        agentguard_url="http://localhost:8000",
        api_key="your-key",
    )
    proxy.run()
"""

from __future__ import annotations

import asyncio
import functools
import json
import logging
import uuid
from typing import Any, Callable, TypeVar

import httpx

logger = logging.getLogger(__name__)

F = TypeVar("F", bound=Callable[..., Any])


class MCPShield:
    """Decorator-based guard for MCP tool handlers.

    Wraps any MCP tool function so that every call is checked against
    the AgentGuard core engine before execution.
    """

    def __init__(
        self,
        *,
        api_key: str = "",
        base_url: str = "http://localhost:8000",
        agent_id: str = "mcp-server",
        timeout: float = 10.0,
        fail_open: bool = True,
    ) -> None:
        self._api_key = api_key
        self._base_url = base_url.rstrip("/")
        self._agent_id = agent_id
        self._timeout = timeout
        self._fail_open = fail_open
        self._session_id: str | None = None
        self._client = httpx.AsyncClient(
            base_url=self._base_url,
            headers={
                "Authorization": f"Bearer {self._api_key}",
                "Content-Type": "application/json",
                "User-Agent": "agentguard-mcp/0.1.0",
            },
            timeout=self._timeout,
        )

    async def _ensure_session(self) -> str:
        """Lazily create a session on first use."""
        if self._session_id:
            return self._session_id
        try:
            resp = await self._client.post("/api/v1/sessions", json={
                "user_message": "",
                "agent_id": self._agent_id,
                "metadata": {"integration": "mcp"},
            })
            resp.raise_for_status()
            self._session_id = resp.json()["session_id"]
        except Exception:
            self._session_id = str(uuid.uuid4())
            logger.warning("AgentGuard session creation failed, using local ID")
        return self._session_id

    async def check(self, tool_name: str, params: dict[str, Any]) -> dict[str, Any]:
        """Check a tool call against the AgentGuard policy engine."""
        session_id = await self._ensure_session()
        try:
            resp = await self._client.post("/api/v1/check", json={
                "session_id": session_id,
                "tool_name": tool_name,
                "params": params,
                "source_id": "mcp/tool",
            })
            resp.raise_for_status()
            return resp.json()
        except Exception as e:
            if self._fail_open:
                logger.warning("AgentGuard check failed (%s), allowing tool call", e)
                return {"action": "ALLOW", "reason": "fail-open", "trace_id": ""}
            raise

    def guard(self, fn: F) -> F:
        """Decorator that guards an MCP tool handler.

        Usage::

            @app.tool()
            @shield.guard
            async def my_tool(param: str) -> str:
                ...
        """
        @functools.wraps(fn)
        async def wrapper(*args: Any, **kwargs: Any) -> Any:
            # Extract tool name from function name
            tool_name = fn.__name__

            # Build params dict from kwargs (MCP passes named params)
            params = dict(kwargs)
            if args:
                params["_positional"] = list(args)

            result = await self.check(tool_name, params)

            if result.get("action") == "BLOCK":
                reason = result.get("reason", "Blocked by security policy")
                raise ToolCallBlocked(tool_name, reason, result.get("trace_id", ""))

            if result.get("action") == "REQUIRE_CONFIRMATION":
                # MCP has no built-in confirmation UI.
                # Block with a descriptive message so the client can surface it.
                reason = result.get("reason", "Requires confirmation")
                raise ToolCallBlocked(
                    tool_name,
                    f"Security confirmation required: {reason}",
                    result.get("trace_id", ""),
                )

            return await fn(*args, **kwargs)

        return wrapper  # type: ignore[return-value]

    async def close(self) -> None:
        await self._client.aclose()


class ToolCallBlocked(Exception):
    """Raised when AgentGuard blocks a tool call."""

    def __init__(self, tool: str, reason: str, trace_id: str) -> None:
        self.tool = tool
        self.reason = reason
        self.trace_id = trace_id
        super().__init__(f"Tool '{tool}' blocked: {reason} (trace_id={trace_id})")


class MCPShieldProxy:
    """Proxy MCP server that intercepts tool calls for security checks.

    Sits between the MCP client and the real MCP server. The client connects
    to the proxy; the proxy connects to the upstream server. Every tool call
    is checked before being forwarded.

    This requires zero changes to existing MCP servers.

    Usage::

        proxy = MCPShieldProxy(
            upstream_command=["python", "-m", "my_mcp_server"],
            agentguard_url="http://localhost:8000",
            api_key="your-key",
        )
        asyncio.run(proxy.run_stdio())
    """

    def __init__(
        self,
        *,
        upstream_command: list[str],
        agentguard_url: str = "http://localhost:8000",
        api_key: str = "",
        agent_id: str = "mcp-proxy",
        fail_open: bool = True,
    ) -> None:
        self._upstream_cmd = upstream_command
        self._shield = MCPShield(
            api_key=api_key,
            base_url=agentguard_url,
            agent_id=agent_id,
            fail_open=fail_open,
        )

    async def run_stdio(self) -> None:
        """Run as a stdio proxy between client and upstream MCP server."""
        # Start upstream MCP server as subprocess
        proc = await asyncio.create_subprocess_exec(
            *self._upstream_cmd,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )

        assert proc.stdin and proc.stdout

        reader = asyncio.StreamReader()
        protocol = asyncio.StreamReaderProtocol(reader)
        await asyncio.get_event_loop().connect_read_pipe(lambda: protocol, __import__("sys").stdin.buffer)

        async def client_to_upstream() -> None:
            """Read from client stdin, intercept tool calls, forward to upstream."""
            while True:
                line = await reader.readline()
                if not line:
                    break

                # Try to parse as JSON-RPC
                try:
                    msg = json.loads(line)
                except (json.JSONDecodeError, UnicodeDecodeError):
                    proc.stdin.write(line)
                    await proc.stdin.drain()
                    continue

                # Intercept tools/call requests
                if msg.get("method") == "tools/call":
                    params = msg.get("params", {})
                    tool_name = params.get("name", "unknown")
                    tool_args = params.get("arguments", {})

                    result = await self._shield.check(tool_name, tool_args)

                    if result.get("action") == "BLOCK":
                        # Send error response back to client
                        error_response = {
                            "jsonrpc": "2.0",
                            "id": msg.get("id"),
                            "error": {
                                "code": -32001,
                                "message": f"Blocked by AgentGuard: {result.get('reason', '')}",
                            },
                        }
                        __import__("sys").stdout.buffer.write(
                            (json.dumps(error_response) + "\n").encode()
                        )
                        __import__("sys").stdout.buffer.flush()
                        continue

                # Forward to upstream
                proc.stdin.write(line)
                await proc.stdin.drain()

        async def upstream_to_client() -> None:
            """Read from upstream stdout, forward to client."""
            while True:
                line = await proc.stdout.readline()
                if not line:
                    break
                __import__("sys").stdout.buffer.write(line)
                __import__("sys").stdout.buffer.flush()

        await asyncio.gather(client_to_upstream(), upstream_to_client())
        await self._shield.close()
