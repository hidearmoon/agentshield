"""Merkle chain for tamper-proof trace spans."""

from __future__ import annotations

import hashlib

from agentguard_core.engine.trace.models import TraceSpan


class MerkleChain:
    """
    Sequential Merkle chain for append-only trace integrity.
    Each span's hash includes the previous span's hash,
    creating a tamper-evident chain.
    """

    GENESIS = "GENESIS"

    def __init__(self) -> None:
        self._last_hash: str = self.GENESIS

    def compute_hash(self, span: TraceSpan) -> str:
        payload = (
            f"{self._last_hash}|{span.trace_id}|{span.span_id}|"
            f"{span.tool_name}|{span.decision}|{span.start_time.isoformat()}"
        )
        current_hash = hashlib.sha256(payload.encode()).hexdigest()
        self._last_hash = current_hash
        return current_hash

    def reset(self) -> None:
        self._last_hash = self.GENESIS

    @staticmethod
    def verify_chain(spans: list[TraceSpan]) -> bool:
        """Verify the integrity of a span sequence."""
        prev_hash = MerkleChain.GENESIS
        for span in spans:
            payload = (
                f"{prev_hash}|{span.trace_id}|{span.span_id}|"
                f"{span.tool_name}|{span.decision}|{span.start_time.isoformat()}"
            )
            expected = hashlib.sha256(payload.encode()).hexdigest()
            if span.merkle_hash != expected:
                return False
            prev_hash = span.merkle_hash
        return True
