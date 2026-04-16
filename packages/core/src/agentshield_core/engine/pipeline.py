"""Central pipeline orchestrator — the core entry point for all security checks."""

from __future__ import annotations

import logging
import time
import uuid
from collections import OrderedDict
from dataclasses import dataclass, field
from datetime import datetime, timezone

from agentshield_core.engine.intent.engine import IntentConsistencyEngine
from agentshield_core.engine.intent.models import Decision, Intent, ToolCall
from agentshield_core.engine.permissions.dynamic import DynamicPermissionEngine
from agentshield_core.engine.trace.engine import TraceEngine
from agentshield_core.engine.trace.models import TraceSpan
from agentshield_core.engine.trust.levels import TrustLevel
from agentshield_core.engine.trust.marker import TrustMarker

logger = logging.getLogger(__name__)


@dataclass
class CheckResult:
    action: str
    reason: str = ""
    trace_id: str = ""
    span_id: str = ""
    engine: str = ""  # Which engine made the decision: rule | anomaly | semantic | permission
    trust_level: str = ""  # Computed trust level for the request
    latency_ms: float = 0.0  # Processing time in milliseconds


MAX_SESSIONS = 10_000
SESSION_TTL_SECONDS = 3600  # 1 hour


@dataclass
class SessionContext:
    session_id: str
    trace_id: str
    agent_id: str
    user_message: str
    intent: Intent
    trust_scopes: list[TrustLevel] = field(default_factory=list)
    tool_call_history: list[ToolCall] = field(default_factory=list)
    metadata: dict = field(default_factory=dict)
    created_at: float = field(default_factory=time.time)

    @property
    def current_trust_level(self) -> TrustLevel:
        if self.trust_scopes:
            return min(self.trust_scopes)
        return TrustLevel.VERIFIED


class Pipeline:
    """
    Central orchestrator wiring sanitization, trust, intent detection,
    permissions, and tracing together. Every request flows through this.
    """

    # Type for optional block callback
    BlockCallback = None  # Callable[[str, str, str, str], Awaitable[None]] in practice

    def __init__(
        self,
        trust_marker: TrustMarker,
        intent_engine: IntentConsistencyEngine,
        permission_engine: DynamicPermissionEngine,
        trace_engine: TraceEngine,
        on_block: object | None = None,
    ):
        self._trust_marker = trust_marker
        self._intent_engine = intent_engine
        self._permission_engine = permission_engine
        self._trace_engine = trace_engine
        self._on_block = on_block  # async callback(tool, reason, trace_id, agent_id)
        self._sessions: OrderedDict[str, SessionContext] = OrderedDict()
        # Performance counters
        self._total_checks = 0
        self._blocked_checks = 0
        self._total_check_time_ms = 0.0

    def _evict_stale_sessions(self) -> None:
        """Remove expired sessions and enforce max capacity."""
        now = time.time()
        # Remove expired sessions
        expired = [sid for sid, ctx in self._sessions.items() if now - ctx.created_at > SESSION_TTL_SECONDS]
        for sid in expired:
            del self._sessions[sid]
        # Enforce max capacity (remove oldest first)
        while len(self._sessions) > MAX_SESSIONS:
            self._sessions.popitem(last=False)

    async def create_session(
        self,
        user_message: str,
        agent_id: str = "",
        metadata: dict | None = None,
    ) -> tuple[str, str]:
        """Create a new session and extract user intent."""
        self._evict_stale_sessions()
        session_id = str(uuid.uuid4())
        trace_id = self._trace_engine.create_trace(session_id, user_message)

        # Extract intent
        await self._intent_engine.on_session_start(session_id, user_message)
        intent_ctx = self._intent_engine.get_context(session_id)

        self._sessions[session_id] = SessionContext(
            session_id=session_id,
            trace_id=trace_id,
            agent_id=agent_id,
            user_message=user_message,
            intent=intent_ctx.intent if intent_ctx else Intent(intent=user_message),
            metadata=metadata or {},
        )

        return session_id, trace_id

    async def check_tool_call(
        self,
        session_id: str,
        tool_name: str,
        tool_params: dict,
        source_id: str = "",
        client_trust_level: str | None = None,
    ) -> CheckResult:
        """
        Main entry point for tool call security check.
        Called by POST /api/v1/check.
        """
        check_start = datetime.now(timezone.utc)
        ctx = self._sessions.get(session_id)
        if not ctx:
            # Auto-create session for stateless usage
            session_id, trace_id = await self.create_session(user_message="", agent_id="")
            ctx = self._sessions[session_id]

        # Step 1: Compute trust level server-side
        claimed = None
        if client_trust_level:
            try:
                claimed = TrustLevel[client_trust_level]
            except KeyError:
                pass  # Invalid client trust level ignored, server decides
        trust_level = self._trust_marker.compute_trust_level(source_id or "unknown", claimed)

        # Step 2: Permission check (fast, no I/O)
        available_tools = self._permission_engine.get_available_tools(
            trust_level=trust_level,
            intent=ctx.intent,
            agent_tools=ctx.metadata.get("agent_tools", []),
        )
        if available_tools and tool_name not in available_tools:
            # Sanitize tool_name to prevent XSS in API responses
            safe_name = tool_name[:100].replace("<", "&lt;").replace(">", "&gt;")
            decision = Decision.block(
                reason=f"Tool '{safe_name}' not permitted at trust level {trust_level.name}",
                engine="permission",
            )
        else:
            # Step 3: Intent consistency check (3-layer cascade)
            # Update context with current request's trust level
            intent_ctx = self._intent_engine.get_context(session_id)
            if intent_ctx:
                intent_ctx.current_data_trust_level = trust_level
            tool_call = ToolCall(name=tool_name, params=tool_params)
            decision = await self._intent_engine.check_tool_call(session_id, tool_call)

        # Step 4: Record span
        drift_score = self._intent_engine.last_anomaly_score
        span_id = str(uuid.uuid4())
        span = TraceSpan(
            trace_id=ctx.trace_id,
            span_id=span_id,
            parent_span_id="",
            agent_id=ctx.agent_id,
            session_id=session_id,
            span_type="tool_call",
            intent=ctx.intent.intent,
            intent_drift_score=drift_score,
            data_trust_level=trust_level.name,
            tool_name=tool_name,
            tool_params=tool_params,
            tool_result_summary="",
            decision=decision.action.value,
            decision_reason=decision.reason,
            decision_engine=decision.engine,
            start_time=check_start,
            end_time=datetime.now(timezone.utc),
        )
        await self._trace_engine.record_span(span)

        # Track history
        ctx.tool_call_history.append(ToolCall(name=tool_name, params=tool_params))

        # Structured log for security monitoring / SIEM
        if decision.action.value == "BLOCK":
            logger.warning(
                "tool_call_blocked: tool=%s trust=%s engine=%s reason=%s",
                tool_name,
                trust_level.name,
                decision.engine,
                decision.reason[:100],
            )
            # Invoke optional block callback (e.g., webhook notification)
            if self._on_block:
                try:
                    await self._on_block(tool_name, decision.reason, ctx.trace_id, ctx.agent_id)
                except Exception:
                    logger.exception("on_block callback failed")
        elif decision.action.value == "REQUIRE_CONFIRMATION":
            logger.info(
                "tool_call_confirmation_required: tool=%s reason=%s",
                tool_name,
                decision.reason[:100],
            )

        # Update performance counters
        elapsed_ms = (datetime.now(timezone.utc) - check_start).total_seconds() * 1000
        self._total_checks += 1
        self._total_check_time_ms += elapsed_ms
        if decision.action.value == "BLOCK":
            self._blocked_checks += 1

        return CheckResult(
            action=decision.action.value,
            reason=decision.reason,
            trace_id=ctx.trace_id,
            span_id=span_id,
            engine=decision.engine,
            trust_level=trust_level.name,
            latency_ms=round(elapsed_ms, 3),
        )

    @property
    def metrics(self) -> dict:
        """Return pipeline performance metrics."""
        avg_ms = self._total_check_time_ms / self._total_checks if self._total_checks else 0
        return {
            "total_checks": self._total_checks,
            "blocked_checks": self._blocked_checks,
            "block_rate": round(self._blocked_checks / self._total_checks, 4) if self._total_checks else 0,
            "avg_check_ms": round(avg_ms, 3),
            "active_sessions": len(self._sessions),
        }

    def reset_metrics(self) -> None:
        """Reset performance counters. Useful for periodic reporting."""
        self._total_checks = 0
        self._blocked_checks = 0
        self._total_check_time_ms = 0.0
