"""AutoGen integration — wraps the function map through Shield."""

from __future__ import annotations

import asyncio
import functools
from typing import Any, Callable

from agentguard.exceptions import ConfirmationRejected, ToolCallBlocked
from agentguard.models import Decision
from agentguard.shield import Shield


class AutoGenShield:
    """Wrap an AutoGen agent's function_map so every call is guarded.

    AutoGen agents maintain a ``function_map`` dict mapping function names
    to callables. This integration wraps each callable so a server check
    runs before execution.

    Usage::

        from autogen import AssistantAgent
        from agentguard import Shield
        from agentguard.integrations import AutoGenShield

        shield = Shield()
        assistant = AssistantAgent(name="assistant", ...)
        AutoGenShield(shield).wrap(assistant)
    """

    def __init__(self, shield: Shield, *, session_id: str | None = None) -> None:
        self._shield = shield
        self._session_id = session_id

    def wrap(self, agent: Any) -> Any:
        """Patch the agent's function_map in-place and return the agent."""
        function_map: dict[str, Callable[..., Any]] | None = getattr(agent, "function_map", None)
        if function_map is None:
            raise TypeError("Expected an object with a .function_map attribute (e.g. autogen.AssistantAgent)")

        patched: dict[str, Callable[..., Any]] = {}
        for name, fn in function_map.items():
            patched[name] = self._wrap_function(name, fn)

        agent.function_map = patched
        return agent

    def _wrap_function(self, tool_name: str, fn: Callable[..., Any]) -> Callable[..., Any]:
        """Return a wrapper that checks with the server before calling fn."""

        @functools.wraps(fn)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            params: dict[str, Any] = {}
            if args:
                params["args"] = list(args)
            if kwargs:
                params.update(kwargs)

            async def _check() -> None:
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

            try:
                loop = asyncio.get_running_loop()
            except RuntimeError:
                loop = None

            if loop is not None and loop.is_running():
                import concurrent.futures

                with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
                    pool.submit(asyncio.run, _check()).result()
            else:
                asyncio.run(_check())

            return fn(*args, **kwargs)

        return wrapper
