"""Claude Agent SDK integration — wraps the tool handler callback."""

from __future__ import annotations

import functools
from typing import Any, Callable, Coroutine

from agentguard.exceptions import ConfirmationRejected, ToolCallBlocked
from agentguard.models import Decision
from agentguard.shield import Shield


class ClaudeAgentGuard:
    """Wrap a Claude Agent SDK tool handler so every call is guarded.

    The Claude Agent SDK uses a callback pattern where a tool handler
    receives the tool name and parameters. This integration wraps that
    handler to perform a server check before execution.

    Usage::

        from claude_agent_sdk import Agent
        from agentguard import Shield
        from agentguard.integrations import ClaudeAgentGuard

        shield = Shield()

        async def my_tool_handler(tool_name: str, params: dict) -> Any:
            ...

        guarded_handler = ClaudeAgentGuard(shield).wrap(my_tool_handler)
        agent = Agent(tool_handler=guarded_handler)
    """

    def __init__(self, shield: Shield, *, session_id: str | None = None) -> None:
        self._shield = shield
        self._session_id = session_id

    def wrap(
        self,
        handler: Callable[..., Coroutine[Any, Any, Any]],
    ) -> Callable[..., Coroutine[Any, Any, Any]]:
        """Return a guarded version of the tool handler callback."""

        @functools.wraps(handler)
        async def guarded_handler(tool_name: str, params: dict, **kwargs: Any) -> Any:
            result = await self._shield._client.check_tool_call(
                session_id=self._session_id or self._shield._default_session_id,
                tool_name=tool_name,
                params=params,
            )

            if result.action is Decision.BLOCK:
                raise ToolCallBlocked(
                    tool=tool_name,
                    reason=result.reason,
                    trace_id=result.trace_id,
                )

            if result.action is Decision.REQUIRE_CONFIRMATION:
                cb = self._shield._config.confirm_callback
                if cb is None:
                    raise ConfirmationRejected(tool=tool_name)
                confirmed = await cb(tool_name, params)
                if not confirmed:
                    raise ConfirmationRejected(tool=tool_name)

            return await handler(tool_name, params, **kwargs)

        return guarded_handler
