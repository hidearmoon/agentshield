"""
AgentShield Security Block for AutoGPT Platform.

AutoGPT Platform uses a graph-based execution engine where Blocks are the
unit of extensibility. This module provides an AgentShieldBlock that can be
placed before any sensitive block in a graph to enforce security policies.

Additionally provides a mixin for existing blocks to add security checks
via the `is_sensitive_action` + HITL review pattern.

Setup:
    1. Copy this file to autogpt_platform/backend/backend/blocks/
    2. The block auto-discovery system will pick it up on next restart
    3. In the AutoGPT UI, add the "AgentShield Security Check" block
       before sensitive blocks in your graph

The block checks tool calls against the AgentShield core engine and
outputs to either the "allowed" or "blocked" pin.
"""

from __future__ import annotations

import logging
import uuid
from typing import Any

import httpx

logger = logging.getLogger("agentshield_autogpt")

# --- Standalone helper for use outside the Block system ---


class AgentShieldChecker:
    """Stateless security checker that calls the AgentShield core engine."""

    def __init__(
        self,
        api_key: str,
        core_url: str = "http://localhost:8000",
        agent_id: str = "autogpt",
        timeout: float = 10.0,
        fail_open: bool = True,
    ) -> None:
        self._fail_open = fail_open
        self._session_id: str | None = None
        self._agent_id = agent_id
        self._client = httpx.Client(
            base_url=core_url.rstrip("/"),
            headers={
                "Authorization": f"Bearer {api_key}",
                "Content-Type": "application/json",
                "User-Agent": "agentshield-autogpt/0.1.0",
            },
            timeout=timeout,
        )

    def _ensure_session(self) -> str:
        if self._session_id:
            return self._session_id
        try:
            resp = self._client.post("/api/v1/sessions", json={
                "user_message": "",
                "agent_id": self._agent_id,
                "metadata": {"integration": "autogpt"},
            })
            resp.raise_for_status()
            self._session_id = resp.json()["session_id"]
        except Exception:
            self._session_id = str(uuid.uuid4())
        return self._session_id

    def check(self, tool_name: str, params: dict[str, Any]) -> dict[str, Any]:
        """Check a tool/block call against AgentShield policy."""
        try:
            resp = self._client.post("/api/v1/check", json={
                "session_id": self._ensure_session(),
                "tool_name": tool_name,
                "params": params,
                "source_id": "autogpt/block",
            })
            resp.raise_for_status()
            return resp.json()
        except Exception as e:
            if self._fail_open:
                logger.warning("AgentShield check failed (%s), allowing", e)
                return {"action": "ALLOW"}
            raise


# --- AutoGPT Block Definition ---
# This follows the AutoGPT Platform Block API.
# When placed in backend/blocks/, it is auto-discovered.

try:
    from backend.blocks._base import Block, BlockCategory, BlockOutput
    from backend.data.model import SchemaField

    class AgentShieldBlockInput:
        """Input schema for the AgentShield security check block."""
        tool_name: str = SchemaField(description="Name of the tool/action to check")
        tool_params: dict = SchemaField(description="Parameters being passed to the tool", default={})
        api_key: str = SchemaField(description="AgentShield API key")
        core_url: str = SchemaField(description="AgentShield core engine URL", default="http://localhost:8000")
        passthrough_data: Any = SchemaField(description="Data to pass through if allowed", default=None)

    class AgentShieldBlockOutput:
        """Output schema for the AgentShield security check block."""
        allowed_data: Any = SchemaField(description="Passthrough data (only on ALLOW)")
        blocked_reason: str = SchemaField(description="Block reason (only on BLOCK)")
        decision: str = SchemaField(description="ALLOW, BLOCK, or REQUIRE_CONFIRMATION")
        trace_id: str = SchemaField(description="AgentShield trace ID for audit")

    class AgentShieldBlock(Block):
        """Check a tool call against AgentShield security policy.

        Place this block before any sensitive block in your graph.
        Connect the 'allowed_data' output to the sensitive block's input,
        and the 'blocked_reason' output to an error handler or user notification.
        """

        def __init__(self):
            super().__init__(
                id="d4e5f6a7-b8c9-4d0e-1f2a-3b4c5d6e7f80",
                description="AgentShield Security Check — validates tool calls against security policy before execution",
                categories={BlockCategory.SAFETY},
                input_schema=AgentShieldBlockInput,
                output_schema=AgentShieldBlockOutput,
            )

        async def run(self, input_data: AgentShieldBlockInput, **kwargs) -> BlockOutput:
            checker = AgentShieldChecker(
                api_key=input_data.api_key,
                core_url=input_data.core_url,
            )

            result = checker.check(input_data.tool_name, input_data.tool_params)
            action = result.get("action", "ALLOW")
            reason = result.get("reason", "")
            trace_id = result.get("trace_id", "")

            yield "decision", action
            yield "trace_id", trace_id

            if action == "ALLOW":
                yield "allowed_data", input_data.passthrough_data
                yield "blocked_reason", ""
            else:
                yield "allowed_data", None
                yield "blocked_reason", reason
                logger.warning(
                    "AgentShield %s: tool=%s reason=%s trace=%s",
                    action, input_data.tool_name, reason, trace_id,
                )

except ImportError:
    # Not running inside AutoGPT Platform — AgentShieldChecker is still usable standalone
    pass
