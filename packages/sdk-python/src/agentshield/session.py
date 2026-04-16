"""ShieldSession — async context manager for guarded agent sessions."""

from __future__ import annotations

from typing import Any, Callable, Coroutine

from agentshield.client import ServerClient
from agentshield.exceptions import ConfirmationRejected, ToolCallBlocked
from agentshield.models import CheckResult, Decision


class GuardedExecutor:
    """Wraps arbitrary async tool calls through the shield check pipeline."""

    def __init__(
        self,
        client: ServerClient,
        session_id: str,
        confirm_callback: Callable[[str, dict], Coroutine[Any, Any, bool]] | None = None,
    ) -> None:
        self._client = client
        self._session_id = session_id
        self._confirm_callback = confirm_callback

    async def execute(
        self,
        tool_name: str,
        params: dict,
        func: Callable[..., Coroutine[Any, Any, Any]],
        *,
        source_id: str = "",
    ) -> Any:
        """Check with the server, enforce the decision, then run the tool."""
        result: CheckResult = await self._client.check_tool_call(
            session_id=self._session_id,
            tool_name=tool_name,
            params=params,
            source_id=source_id,
        )

        if result.action is Decision.BLOCK:
            raise ToolCallBlocked(
                tool=tool_name,
                reason=result.reason,
                trace_id=result.trace_id,
            )

        if result.action is Decision.REQUIRE_CONFIRMATION:
            if self._confirm_callback is None:
                raise ConfirmationRejected(tool=tool_name)
            confirmed = await self._confirm_callback(tool_name, params)
            if not confirmed:
                raise ConfirmationRejected(tool=tool_name)

        return await func(**params)


class ShieldSession:
    """Async context manager representing a guarded agent session.

    Usage::

        async with shield.session("Summarize my emails") as s:
            result = await s.guarded_executor.execute(
                "read_inbox", {"limit": 10}, read_inbox_fn
            )
    """

    def __init__(
        self,
        client: ServerClient,
        user_message: str,
        agent_id: str = "",
        metadata: dict | None = None,
        confirm_callback: Callable[[str, dict], Coroutine[Any, Any, bool]] | None = None,
    ) -> None:
        self._client = client
        self._user_message = user_message
        self._agent_id = agent_id
        self._metadata = metadata or {}
        self._confirm_callback = confirm_callback
        self.session_id: str = ""
        self.trace_id: str = ""
        self._executor: GuardedExecutor | None = None

    async def __aenter__(self) -> ShieldSession:
        info = await self._client.create_session(
            user_message=self._user_message,
            agent_id=self._agent_id,
            metadata=self._metadata,
        )
        self.session_id = info.session_id
        self.trace_id = info.trace_id
        self._executor = GuardedExecutor(
            client=self._client,
            session_id=self.session_id,
            confirm_callback=self._confirm_callback,
        )
        return self

    async def __aexit__(self, exc_type: type | None, exc_val: BaseException | None, exc_tb: object) -> None:
        # Session lifecycle is tracked server-side; nothing to tear down locally.
        pass

    @property
    def guarded_executor(self) -> GuardedExecutor:
        """Return the executor that routes tool calls through the server check."""
        if self._executor is None:
            raise RuntimeError("ShieldSession must be used as an async context manager")
        return self._executor
