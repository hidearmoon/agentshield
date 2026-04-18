"""LangChain integration — wraps each tool's _arun through Shield.guard."""

from __future__ import annotations

import functools
from typing import Any

from agentguard.shield import Shield


class LangChainShield:
    """Wrap a LangChain agent so every tool call is guarded by AgentGuard.

    Works by monkey-patching each tool's ``_arun`` method to route through
    ``shield.guard`` before execution.

    Usage::

        from langchain.agents import AgentExecutor
        from agentguard import Shield
        from agentguard.integrations import LangChainShield

        shield = Shield()
        agent = AgentExecutor(agent=..., tools=[search_tool, calc_tool])
        guarded_agent = LangChainShield(shield).wrap(agent)
        result = await guarded_agent.ainvoke({"input": "..."})
    """

    def __init__(self, shield: Shield, *, session_id: str | None = None) -> None:
        self._shield = shield
        self._session_id = session_id

    def wrap(self, agent_executor: Any) -> Any:
        """Patch every tool on the agent executor and return it."""
        try:
            tools = agent_executor.tools
        except AttributeError as exc:
            raise TypeError("Expected an object with a .tools attribute (e.g. AgentExecutor)") from exc

        for tool in tools:
            self._patch_tool(tool)
        return agent_executor

    def _patch_tool(self, tool: Any) -> None:
        """Replace tool._arun with a guarded wrapper."""
        original_arun = tool._arun  # noqa: SLF001

        @functools.wraps(original_arun)
        async def guarded_arun(*args: Any, **kwargs: Any) -> Any:
            # Build a params dict for the check call
            params: dict[str, Any] = {}
            if args:
                params["args"] = list(args)
            if kwargs:
                params.update(kwargs)

            tool_name = getattr(tool, "name", tool.__class__.__name__)

            from agentguard.models import Decision
            from agentguard.exceptions import ToolCallBlocked, ConfirmationRejected

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

            return await original_arun(*args, **kwargs)

        tool._arun = guarded_arun  # noqa: SLF001
