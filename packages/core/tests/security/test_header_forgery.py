"""Security tests: Proxy header forgery prevention."""

from agentshield_core.engine.trust.levels import TrustLevel
from agentshield_core.engine.trust.marker import TrustMarker


class TestHeaderForgery:
    """Verify that client-provided trust levels cannot bypass server-side computation."""

    def test_cannot_elevate_external_to_trusted(self):
        marker = TrustMarker()
        # Email source is EXTERNAL, client claims TRUSTED
        result = marker.compute_trust_level("email/gmail", TrustLevel.TRUSTED)
        assert result == TrustLevel.EXTERNAL  # Server wins

    def test_cannot_elevate_untrusted_to_verified(self):
        marker = TrustMarker()
        result = marker.compute_trust_level("unknown", TrustLevel.VERIFIED)
        assert result == TrustLevel.UNTRUSTED

    def test_cannot_elevate_internal_to_trusted(self):
        marker = TrustMarker()
        result = marker.compute_trust_level("agent/sub-agent", TrustLevel.TRUSTED)
        assert result == TrustLevel.INTERNAL

    def test_all_trust_levels_cannot_be_upgraded(self):
        marker = TrustMarker()
        test_cases = [
            ("email/test", TrustLevel.EXTERNAL, TrustLevel.TRUSTED),
            ("email/test", TrustLevel.EXTERNAL, TrustLevel.VERIFIED),
            ("email/test", TrustLevel.EXTERNAL, TrustLevel.INTERNAL),
            ("web/test", TrustLevel.EXTERNAL, TrustLevel.TRUSTED),
            ("agent/test", TrustLevel.INTERNAL, TrustLevel.TRUSTED),
            ("agent/test", TrustLevel.INTERNAL, TrustLevel.VERIFIED),
            ("unknown", TrustLevel.UNTRUSTED, TrustLevel.TRUSTED),
        ]
        for source, expected_level, claimed_level in test_cases:
            result = marker.compute_trust_level(source, claimed_level)
            assert result == expected_level, (
                f"Source {source}: expected {expected_level}, got {result} when client claimed {claimed_level}"
            )
