"""Shield — primary entry point for the AgentGuard Python SDK."""

from __future__ import annotations

import functools
import inspect
from typing import Any, Callable, Coroutine, TypeVar

from agentguard.client import ServerClient
from agentguard.config import ShieldConfig, resolve_config
from agentguard.exceptions import ConfirmationRejected, ToolCallBlocked
from agentguard.models import (
    CheckResult,
    Decision,
    ExtractedData,
    MarkedData,
    SanitizedData,
)
from agentguard.session import ShieldSession

F = TypeVar("F", bound=Callable[..., Coroutine[Any, Any, Any]])


class Shield:
    """Lightweight security guardrail for AI agent tool calls.

    All security logic lives server-side. This class captures context,
    forwards it to the core engine, and enforces the returned decision.

    Usage::

        shield = Shield()  # reads AGENTGUARD_API_KEY from env

        @shield.guard
        async def send_email(to: str, body: str) -> str:
            ...

        async with shield.session("Handle user request") as s:
            await s.guarded_executor.execute("send_email", {"to": "a@b.com", "body": "hi"}, send_email)
    """

    def __init__(
        self,
        *,
        api_key: str | None = None,
        base_url: str | None = None,
        timeout: float | None = None,
        max_retries: int | None = None,
        agent_id: str | None = None,
        confirm_callback: Callable[[str, dict], Coroutine[Any, Any, bool]] | None = None,
    ) -> None:
        self._config: ShieldConfig = resolve_config(
            api_key=api_key,
            base_url=base_url,
            timeout=timeout,
            max_retries=max_retries,
            agent_id=agent_id,
            confirm_callback=confirm_callback,
        )
        self._client = ServerClient(self._config)
        self._default_session_id = "__standalone__"

    # ------------------------------------------------------------------
    # guard decorator
    # ------------------------------------------------------------------

    def guard(
        self,
        func: F | None = None,
        *,
        tool_name: str | None = None,
        session_id: str | None = None,
    ) -> F | Callable[[F], F]:
        """Decorator that interposes a server check before every call.

        Can be used bare (``@shield.guard``) or with options
        (``@shield.guard(tool_name="custom_name")``).
        """

        def decorator(fn: F) -> F:
            resolved_tool_name = tool_name or fn.__name__

            @functools.wraps(fn)
            async def wrapper(*args: Any, **kwargs: Any) -> Any:
                # Build params dict from the function signature
                sig = inspect.signature(fn)
                bound = sig.bind(*args, **kwargs)
                bound.apply_defaults()
                params = dict(bound.arguments)

                sid = session_id or self._default_session_id

                result: CheckResult = await self._client.check_tool_call(
                    session_id=sid,
                    tool_name=resolved_tool_name,
                    params=params,
                )

                if result.action is Decision.BLOCK:
                    raise ToolCallBlocked(
                        tool=resolved_tool_name,
                        reason=result.reason,
                        trace_id=result.trace_id,
                    )

                if result.action is Decision.REQUIRE_CONFIRMATION:
                    cb = self._config.confirm_callback
                    if cb is None:
                        raise ConfirmationRejected(tool=resolved_tool_name)
                    confirmed = await cb(resolved_tool_name, params)  # type: ignore[misc]
                    if not confirmed:
                        raise ConfirmationRejected(tool=resolved_tool_name)

                return await fn(*args, **kwargs)

            return wrapper  # type: ignore[return-value]

        if func is not None:
            # Used as @shield.guard (no parentheses)
            return decorator(func)
        # Used as @shield.guard(tool_name="...")
        return decorator  # type: ignore[return-value]

    # ------------------------------------------------------------------
    # session context manager factory
    # ------------------------------------------------------------------

    def session(
        self,
        user_message: str,
        *,
        agent_id: str | None = None,
        metadata: dict | None = None,
    ) -> ShieldSession:
        """Create a guarded session (use as ``async with shield.session(...) as s:``)."""
        return ShieldSession(
            client=self._client,
            user_message=user_message,
            agent_id=agent_id or self._config.agent_id,
            metadata=metadata,
            confirm_callback=self._config.confirm_callback,  # type: ignore[arg-type]
        )

    # ------------------------------------------------------------------
    # manual check
    # ------------------------------------------------------------------

    async def check(
        self,
        tool_name: str,
        params: dict | None = None,
        *,
        session_id: str | None = None,
        source_id: str = "",
    ) -> CheckResult:
        """Manually check a tool call without executing it.

        Useful when you want to inspect the decision before running the tool.

        Usage::

            result = await shield.check("send_email", {"to": "user@test.com"})
            if result.action == Decision.ALLOW:
                await send_email(to="user@test.com")
        """
        return await self._client.check_tool_call(
            session_id=session_id or self._default_session_id,
            tool_name=tool_name,
            params=params or {},
            source_id=source_id,
        )

    # ------------------------------------------------------------------
    # data-plane helpers (thin forwarding)
    # ------------------------------------------------------------------

    async def sanitize(
        self,
        data: str,
        *,
        source: str,
        data_type: str = "auto",
    ) -> SanitizedData:
        """Forward data to the server-side sanitization pipeline."""
        return await self._client.sanitize(data=data, source=source, data_type=data_type)

    async def two_phase_extract(
        self,
        data: str,
        *,
        schema_name: str,
    ) -> ExtractedData:
        """Forward data to the server-side two-phase extraction pipeline."""
        return await self._client.extract(data=data, schema_name=schema_name)

    async def mark_data(
        self,
        data: str,
        *,
        source_id: str,
        client_trust_level: str | None = None,
    ) -> MarkedData:
        """Forward data to the server-side trust marker."""
        return await self._client.mark_data(
            data=data,
            source_id=source_id,
            client_trust_level=client_trust_level,
        )

    # ------------------------------------------------------------------
    # lifecycle
    # ------------------------------------------------------------------

    async def close(self) -> None:
        """Release HTTP resources."""
        await self._client.close()

    async def __aenter__(self) -> Shield:
        return self

    async def __aexit__(self, *args: object) -> None:
        await self.close()
