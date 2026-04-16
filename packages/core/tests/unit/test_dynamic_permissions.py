"""Tests for Dynamic Permission Engine."""

import pytest
from agentshield_core.engine.trust.levels import TrustLevel
from agentshield_core.engine.permissions.dynamic import DynamicPermissionEngine


class TestDynamicPermissions:
    @pytest.fixture
    def engine(self) -> DynamicPermissionEngine:
        return DynamicPermissionEngine()

    def test_trusted_allows_everything(self, engine: DynamicPermissionEngine):
        result = engine.get_available_tools(TrustLevel.TRUSTED)
        assert result == []  # Empty = all allowed

    def test_external_restricts_dangerous_tools(self, engine: DynamicPermissionEngine):
        tools = ["send_email", "summarize", "classify", "query_database", "execute_code"]
        result = engine.get_available_tools(
            TrustLevel.EXTERNAL,
            agent_tools=tools,
        )
        assert "send_email" not in result
        assert "query_database" not in result
        assert "execute_code" not in result
        assert "summarize" in result
        assert "classify" in result

    def test_untrusted_minimal_tools(self, engine: DynamicPermissionEngine):
        tools = ["send_email", "summarize", "classify", "query_database"]
        result = engine.get_available_tools(
            TrustLevel.UNTRUSTED,
            agent_tools=tools,
        )
        assert "summarize" in result
        assert "classify" in result
        assert "send_email" not in result
