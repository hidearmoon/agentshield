"""Tests for TrustMarker — server-side trust level computation."""

from agentguard_core.engine.trust.levels import TrustLevel
from agentguard_core.engine.trust.marker import TrustMarker


class TestTrustMarker:
    def test_known_source_returns_correct_level(self, trust_marker: TrustMarker):
        assert trust_marker.compute_trust_level("user_input") == TrustLevel.VERIFIED
        assert trust_marker.compute_trust_level("system") == TrustLevel.TRUSTED

    def test_wildcard_matching(self, trust_marker: TrustMarker):
        assert trust_marker.compute_trust_level("email/gmail") == TrustLevel.EXTERNAL
        assert trust_marker.compute_trust_level("web/google") == TrustLevel.EXTERNAL
        assert trust_marker.compute_trust_level("agent/helper") == TrustLevel.INTERNAL

    def test_unknown_source_defaults_to_untrusted(self, trust_marker: TrustMarker):
        assert trust_marker.compute_trust_level("random_source") == TrustLevel.UNTRUSTED

    def test_client_cannot_upgrade_trust(self, trust_marker: TrustMarker):
        """CRITICAL: Client-claimed level can never be higher than server-computed."""
        # email/* is EXTERNAL (2), client claims TRUSTED (5) — should stay EXTERNAL
        result = trust_marker.compute_trust_level("email/gmail", TrustLevel.TRUSTED)
        assert result == TrustLevel.EXTERNAL

    def test_client_can_downgrade_trust(self, trust_marker: TrustMarker):
        """Client can claim lower trust (more conservative)."""
        result = trust_marker.compute_trust_level("email/gmail", TrustLevel.UNTRUSTED)
        assert result == TrustLevel.UNTRUSTED

    def test_client_same_level_uses_server(self, trust_marker: TrustMarker):
        result = trust_marker.compute_trust_level("email/gmail", TrustLevel.EXTERNAL)
        assert result == TrustLevel.EXTERNAL

    def test_registered_source_overrides_mapping(self, trust_marker: TrustMarker):
        trust_marker.register_source("email/trusted-partner", TrustLevel.INTERNAL)
        assert trust_marker.compute_trust_level("email/trusted-partner") == TrustLevel.INTERNAL
        # Other email sources still EXTERNAL
        assert trust_marker.compute_trust_level("email/random") == TrustLevel.EXTERNAL

    def test_mark_creates_marked_data(self, trust_marker: TrustMarker):
        marked = trust_marker.mark("test data", "email/gmail")
        assert marked.trust_level == TrustLevel.EXTERNAL
        assert marked.source_id == "email/gmail"
        assert marked.content == "test data"

    def test_get_effective_tools_filters_by_trust(self, trust_marker: TrustMarker):
        all_tools = ["send_email", "query_database", "summarize", "classify"]
        # EXTERNAL trust restricts send_email and query_database
        effective = trust_marker.get_effective_tools(TrustLevel.EXTERNAL, all_tools)
        assert "send_email" not in effective
        assert "query_database" not in effective
        assert "summarize" in effective
