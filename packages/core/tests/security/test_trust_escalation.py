"""Security tests: Trust level escalation attempts."""

from agentshield_core.engine.trust.levels import TrustLevel
from agentshield_core.engine.trust.marker import TrustMarker
from agentshield_core.engine.permissions.dynamic import DynamicPermissionEngine


class TestTrustEscalation:
    def test_external_data_cannot_access_send_tools(self):
        engine = DynamicPermissionEngine()
        tools = ["send_email", "query_database", "summarize", "classify"]
        available = engine.get_available_tools(TrustLevel.EXTERNAL, agent_tools=tools)
        assert "send_email" not in available
        assert "query_database" not in available

    def test_untrusted_data_minimal_tools(self):
        engine = DynamicPermissionEngine()
        tools = ["send_email", "execute_code", "summarize", "classify", "delete_all"]
        available = engine.get_available_tools(TrustLevel.UNTRUSTED, agent_tools=tools)
        assert "send_email" not in available
        assert "execute_code" not in available
        assert "delete_all" not in available
        assert set(available).issubset({"summarize", "classify"})

    def test_agent_data_restricted(self):
        """Data from other agents should be INTERNAL, not TRUSTED."""
        marker = TrustMarker()
        level = marker.compute_trust_level("agent/sub-agent")
        assert level == TrustLevel.INTERNAL
        assert level < TrustLevel.TRUSTED

    def test_cross_agent_trust_downgrade(self):
        """Cross-agent data transfer always downgrades trust."""
        marker = TrustMarker()
        # Even if the source agent was processing TRUSTED data,
        # data passed to another agent becomes INTERNAL
        level = marker.compute_trust_level("agent/trusted-agent")
        assert level == TrustLevel.INTERNAL
