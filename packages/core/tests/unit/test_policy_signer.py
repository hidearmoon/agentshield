"""Tests for Ed25519 policy signing."""

import pytest
from agentshield_core.policy.signer import PolicySigner


class TestPolicySigner:
    def test_sign_and_verify_roundtrip(self):
        signer = PolicySigner()
        policy = {"name": "default", "version": 1, "rules": []}
        signature = signer.sign(policy)
        assert signer.verify(policy, signature)

    def test_tampered_policy_fails_verification(self):
        signer = PolicySigner()
        policy = {"name": "default", "version": 1, "rules": []}
        signature = signer.sign(policy)
        # Tamper with policy
        policy["version"] = 2
        assert not signer.verify(policy, signature)

    def test_wrong_key_fails_verification(self):
        signer1 = PolicySigner()
        signer2 = PolicySigner()
        policy = {"name": "default", "version": 1}
        signature = signer1.sign(policy)
        assert not signer2.verify(policy, signature)

    def test_verify_only_key(self):
        signing_key, verify_key = PolicySigner.generate_keypair()
        signer = PolicySigner(signing_key=signing_key)
        verifier = PolicySigner(verify_key=verify_key)
        policy = {"test": True}
        signature = signer.sign(policy)
        assert verifier.verify(policy, signature)

    def test_generate_keypair(self):
        sk, vk = PolicySigner.generate_keypair()
        assert len(sk) == 32
        assert len(vk) == 32

    def test_sign_without_signing_key_raises(self):
        """Verify-only signer cannot sign."""
        _, vk = PolicySigner.generate_keypair()
        verifier = PolicySigner(verify_key=vk)
        with pytest.raises(ValueError, match="No signing key"):
            verifier.sign({"test": True})

    def test_canonical_form_is_deterministic(self):
        """Key ordering and separators should be deterministic."""
        signer = PolicySigner()
        # Different key order, same content
        policy1 = {"b": 2, "a": 1}
        policy2 = {"a": 1, "b": 2}
        sig1 = signer.sign(policy1)
        sig2 = signer.sign(policy2)
        assert sig1 == sig2  # sort_keys=True ensures same canonical form

    def test_nested_policy_signing(self):
        """Complex nested policy should sign correctly."""
        signer = PolicySigner()
        policy = {
            "name": "complex",
            "version": 3,
            "rules": [
                {"name": "rule1", "action": "BLOCK", "condition": {"tool": "delete"}},
                {"name": "rule2", "action": "ALLOW", "condition": {"trust": "VERIFIED"}},
            ],
            "metadata": {"author": "admin", "timestamp": "2026-01-01"},
        }
        sig = signer.sign(policy)
        assert signer.verify(policy, sig)

        # Modify nested field
        policy["rules"][0]["action"] = "ALLOW"
        assert not signer.verify(policy, sig)
