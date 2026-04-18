"""CrewAI integration — wraps Crew tool execution through Shield."""

from __future__ import annotations

import functools
from typing import Any

from agentguard.exceptions import ConfirmationRejected, ToolCallBlocked
from agentguard.models import Decision
from agentguard.shield import Shield


class CrewAIShield:
    """Wrap a CrewAI Crew so every tool invocation is guarded.

    Works by patching each tool's ``_run`` method on the crew's agents.

    Usage::

        from crewai import Crew, Agent, Task
        from agentguard import Shield
        from agentguard.integrations import CrewAIShield

        shield = Shield()
        crew = Crew(agents=[agent], tasks=[task])
        guarded_crew = CrewAIShield(shield).wrap(crew)
        result = guarded_crew.kickoff()
    """

    def __init__(self, shield: Shield, *, session_id: str | None = None) -> None:
        self._shield = shield
        self._session_id = session_id

    def wrap(self, crew: Any) -> Any:
        """Patch every tool on every agent in the crew."""
        agents = getattr(crew, "agents", [])
        for agent in agents:
            tools = getattr(agent, "tools", [])
            for tool in tools:
                self._patch_tool(tool)
        return crew

    def _patch_tool(self, tool: Any) -> None:
        """Replace tool._run with a guarded wrapper."""
        original_run = tool._run  # noqa: SLF001

        @functools.wraps(original_run)
        def guarded_run(*args: Any, **kwargs: Any) -> Any:
            # CrewAI tools are synchronous; we need to run the async check
            # in a synchronous context.
            import asyncio

            params: dict[str, Any] = {}
            if args:
                params["args"] = list(args)
            if kwargs:
                params.update(kwargs)

            tool_name = getattr(tool, "name", tool.__class__.__name__)

            async def _check_and_run() -> Any:
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

            # Run the check; if we're already in an event loop, use it.
            try:
                loop = asyncio.get_running_loop()
            except RuntimeError:
                loop = None

            if loop is not None and loop.is_running():
                # Schedule as a task and run sync in a nested fashion.
                import concurrent.futures

                with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
                    pool.submit(asyncio.run, _check_and_run()).result()
            else:
                asyncio.run(_check_and_run())

            return original_run(*args, **kwargs)

        tool._run = guarded_run  # noqa: SLF001
