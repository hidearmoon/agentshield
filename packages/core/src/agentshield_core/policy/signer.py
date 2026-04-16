"""Ed25519 policy signing and verification."""

from __future__ import annotations

import json

from nacl.signing import SigningKey, VerifyKey
from nacl.exceptions import BadSignatureError


class PolicySigner:
    """Sign and verify policies using Ed25519."""

    def __init__(self, signing_key: bytes | None = None, verify_key: bytes | None = None):
        if signing_key:
            self._signing_key = SigningKey(signing_key)
            self._verify_key = self._signing_key.verify_key
        elif verify_key:
            self._signing_key = None
            self._verify_key = VerifyKey(verify_key)
        else:
            # Generate new keypair
            self._signing_key = SigningKey.generate()
            self._verify_key = self._signing_key.verify_key

    @property
    def verify_key_bytes(self) -> bytes:
        return bytes(self._verify_key)

    @property
    def signing_key_bytes(self) -> bytes | None:
        return bytes(self._signing_key) if self._signing_key else None

    def sign(self, policy_content: dict) -> bytes:
        """Sign policy content, return signature bytes."""
        if self._signing_key is None:
            raise ValueError("No signing key available")
        canonical = json.dumps(policy_content, sort_keys=True, separators=(",", ":"))
        signed = self._signing_key.sign(canonical.encode())
        return signed.signature

    def verify(self, policy_content: dict, signature: bytes) -> bool:
        """Verify policy signature. Returns True if valid."""
        canonical = json.dumps(policy_content, sort_keys=True, separators=(",", ":"))
        try:
            self._verify_key.verify(canonical.encode(), signature)
            return True
        except BadSignatureError:
            return False

    @classmethod
    def generate_keypair(cls) -> tuple[bytes, bytes]:
        """Generate a new Ed25519 keypair. Returns (signing_key, verify_key)."""
        sk = SigningKey.generate()
        return bytes(sk), bytes(sk.verify_key)
