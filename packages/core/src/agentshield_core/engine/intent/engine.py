"""Intent Consistency Engine — orchestrates the 3-layer detection cascade."""

from __future__ import annotations

import json

from agentshield_core.config import settings
from agentshield_core.engine.intent.models import (
    ToolCall,
    IntentContext,
    Decision,
    Intent,
)
from agentshield_core.engine.intent.rule_engine import RuleEngine
from agentshield_core.engine.intent.anomaly import AnomalyDetector
from agentshield_core.engine.intent.semantic import SemanticChecker
from agentshield_core.llm.client import LLMClient, LLMMessage


class IntentConsistencyEngine:
    """
    Orchestrates 3-layer intent consistency detection:
    1. Rule Engine (ms) — deterministic, built-in + custom rules
    2. Anomaly Detector (ms) — statistical feature scoring
    3. Semantic Checker (500ms-2s) — LLM-based, only when suspicious

    Thresholds:
    - score < SUSPICIOUS (0.6): ALLOW (no LLM call)
    - SUSPICIOUS <= score < ANOMALY (0.85): trigger semantic check
    - score >= ANOMALY (0.85): BLOCK (no LLM call needed)
    """

    def __init__(
        self,
        llm_client: LLMClient,
        rule_engine: RuleEngine | None = None,
        anomaly_detector: AnomalyDetector | None = None,
        semantic_checker: SemanticChecker | None = None,
    ):
        self._llm = llm_client
        self._rule_engine = rule_engine or RuleEngine()
        self._anomaly_detector = anomaly_detector or AnomalyDetector()
        self._semantic_checker = semantic_checker or SemanticChecker(llm_client)
        self._sessions: dict[str, IntentContext] = {}
        self._session_risk: dict[str, float] = {}  # Cumulative risk per session

    async def on_session_start(self, session_id: str, user_message: str) -> None:
        """Extract and record user intent at session start."""
        intent = await self._extract_intent(user_message)
        self._sessions[session_id] = IntentContext(
            original_message=user_message,
            intent=intent,
            allowed_tool_categories=intent.expected_tools,
        )

    def get_context(self, session_id: str) -> IntentContext | None:
        return self._sessions.get(session_id)

    async def check_tool_call(self, session_id: str, tool_call: ToolCall) -> Decision:
        """
        3-layer cascade check. Returns ALLOW / BLOCK / REQUIRE_CONFIRMATION.
        """
        context = self._sessions.get(session_id)
        if not context:
            return Decision.allow()

        # Layer 1: Rule engine (microseconds)
        rule_result = self._rule_engine.check(tool_call, context)
        if rule_result.is_definitive:
            return rule_result.decision

        # Layer 2: Anomaly detection (sub-millisecond)
        anomaly_result = self._anomaly_detector.check(tool_call, context)

        # Apply session-level risk accumulation
        # If previous checks in this session had elevated scores,
        # the effective score gets a boost (escalating suspicion)
        session_risk = self._session_risk.get(session_id, 0.0)
        effective_score = min(1.0, anomaly_result.score + session_risk * 0.1)
        self._last_anomaly_score = effective_score

        # Track cumulative risk for this session
        if anomaly_result.score > 0.1:
            self._session_risk[session_id] = min(1.0, session_risk + anomaly_result.score * 0.2)

        if effective_score >= settings.anomaly_threshold:
            return Decision.block(
                reason=f"Anomaly detected: {anomaly_result.reason}",
                engine="anomaly",
            )

        # Layer 3: Semantic check (500ms-2s, only when suspicious)
        if effective_score >= settings.suspicious_threshold:
            semantic_decision = await self._semantic_checker.check(tool_call, context)
            return semantic_decision

        # All clear
        return Decision.allow()

    @property
    def last_anomaly_score(self) -> float:
        """The anomaly score from the most recent check_tool_call."""
        return getattr(self, "_last_anomaly_score", 0.0)

    async def _extract_intent(self, user_message: str) -> Intent:
        """Extract structured intent from user message using LLM."""
        if not user_message:
            return Intent(intent="unknown")

        response = await self._llm.extract_json(
            [
                LLMMessage(
                    role="system",
                    content=(
                        "Analyze the user's request. Output JSON with:\n"
                        '{"intent": "what they want", '
                        '"expected_tools": ["list", "of", "tool", "categories"], '
                        '"sensitive_data_involved": true/false}'
                    ),
                ),
                LLMMessage(role="user", content=user_message),
            ]
        )

        try:
            data = json.loads(response)
            return Intent(
                intent=data.get("intent", user_message),
                expected_tools=data.get("expected_tools", []),
                sensitive_data_involved=data.get("sensitive_data_involved", False),
            )
        except (json.JSONDecodeError, KeyError):
            return Intent(intent=user_message)
