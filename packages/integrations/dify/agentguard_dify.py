"""
AgentGuard integration for Dify — intercepts all tool calls at the ToolEngine chokepoint.

Dify routes every tool execution (agent mode and workflow mode) through
ToolEngine._invoke(). This module patches that method to run AgentGuard
checks before each tool executes.

Setup:
    1. Start AgentGuard core engine
    2. Import and call install() at Dify startup (e.g., in app.py or a custom extension)

    from agentguard_dify import install
    install(api_key="your-key", core_url="http://localhost:8000")

How it works:
    - Patches ToolEngine._invoke (the single chokepoint for all tool execution)
    - Before each tool runs, sends tool name + params to AgentGuard
    - BLOCK → yields an error ToolInvokeMessage instead of executing
    - REQUIRE_CONFIRMATION → blocks with descriptive message
    - ALLOW → proceeds to original execution
    - Fail-open: if AgentGuard is unreachable, tool call proceeds
"""

from __future__ import annotations

import logging
from typing import Any, Generator

import httpx

logger = logging.getLogger("agentguard_dify")

_client: httpx.Client | None = None
_session_id: str | None = None
_config: dict[str, Any] = {}


def install(
    *,
    api_key: str,
    core_url: str = "http://localhost:8000",
    agent_id: str = "dify",
    fail_open: bool = True,
    timeout: float = 10.0,
) -> None:
    """Patch Dify's ToolEngine to route all tool calls through AgentGuard.

    Call this once at application startup.
    """
    global _client, _config

    _config = {
        "api_key": api_key,
        "core_url": core_url.rstrip("/"),
        "agent_id": agent_id,
        "fail_open": fail_open,
    }

    _client = httpx.Client(
        base_url=_config["core_url"],
        headers={
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
            "User-Agent": "agentguard-dify/0.1.0",
        },
        timeout=timeout,
    )

    _patch_tool_engine()
    logger.info("AgentGuard installed — guarding all Dify tool calls via %s", core_url)


def _ensure_session() -> str:
    global _session_id
    if _session_id:
        return _session_id

    try:
        resp = _client.post("/api/v1/sessions", json={
            "user_message": "",
            "agent_id": _config.get("agent_id", "dify"),
            "metadata": {"integration": "dify"},
        })
        resp.raise_for_status()
        _session_id = resp.json()["session_id"]
    except Exception:
        import uuid
        _session_id = str(uuid.uuid4())
    return _session_id


def _check_tool_call(tool_name: str, tool_provider: str, params: dict) -> dict:
    """Check a tool call against AgentGuard policy."""
    try:
        resp = _client.post("/api/v1/check", json={
            "session_id": _ensure_session(),
            "tool_name": f"{tool_provider}/{tool_name}" if tool_provider else tool_name,
            "params": params,
            "source_id": "dify/tool",
        })
        resp.raise_for_status()
        return resp.json()
    except Exception as e:
        if _config.get("fail_open", True):
            logger.warning("AgentGuard check failed (%s), allowing tool call", e)
            return {"action": "ALLOW"}
        raise


def _patch_tool_engine() -> None:
    """Monkey-patch ToolEngine._invoke to add security checks."""
    try:
        from core.tools.tool_engine import ToolEngine
    except ImportError:
        logger.error("Cannot import ToolEngine — is this running inside Dify?")
        return

    original_invoke = ToolEngine._invoke.__func__

    @staticmethod
    def guarded_invoke(
        tool: Any,
        tool_parameters: dict,
        user_id: str,
        conversation_id: str | None = None,
        app_id: str | None = None,
        message_id: str | None = None,
    ) -> Generator:
        # Extract tool identity
        tool_name = ""
        tool_provider = ""
        try:
            tool_name = tool.entity.identity.name
            tool_provider = tool.entity.identity.provider
        except AttributeError:
            tool_name = type(tool).__name__

        # Security check
        result = _check_tool_call(tool_name, tool_provider, tool_parameters)
        action = result.get("action", "ALLOW")

        if action == "BLOCK":
            reason = result.get("reason", "Blocked by security policy")
            trace_id = result.get("trace_id", "")
            logger.warning(
                "AgentGuard BLOCKED: tool=%s/%s reason=%s trace=%s",
                tool_provider, tool_name, reason, trace_id,
            )
            # Yield a text message indicating the block
            from core.tools.entities.tool_entities import ToolInvokeMessage
            yield ToolInvokeMessage(
                type=ToolInvokeMessage.MessageType.TEXT,
                message=ToolInvokeMessage.TextMessage(
                    text=f"[Security] Tool call blocked: {reason}"
                ),
            )
            return

        if action == "REQUIRE_CONFIRMATION":
            reason = result.get("reason", "Requires confirmation")
            logger.info("AgentGuard CONFIRM: tool=%s/%s reason=%s", tool_provider, tool_name, reason)
            from core.tools.entities.tool_entities import ToolInvokeMessage
            yield ToolInvokeMessage(
                type=ToolInvokeMessage.MessageType.TEXT,
                message=ToolInvokeMessage.TextMessage(
                    text=f"[Security] Confirmation required: {reason}"
                ),
            )
            return

        # ALLOW — proceed to original
        yield from original_invoke(
            tool, tool_parameters, user_id, conversation_id, app_id, message_id
        )

    ToolEngine._invoke = guarded_invoke
    logger.info("ToolEngine._invoke patched with AgentGuard guard")
