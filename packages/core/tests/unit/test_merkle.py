"""Tests for Merkle chain integrity."""

from datetime import datetime, timezone

from agentshield_core.engine.trace.models import TraceSpan
from agentshield_core.engine.trace.merkle import MerkleChain


def _make_span(trace_id: str = "trace-1", span_id: str = "span-1", tool: str = "test") -> TraceSpan:
    now = datetime.now(timezone.utc)
    return TraceSpan(
        trace_id=trace_id,
        span_id=span_id,
        parent_span_id="",
        agent_id="agent-1",
        session_id="session-1",
        span_type="tool_call",
        intent="test intent",
        intent_drift_score=0.0,
        data_trust_level="VERIFIED",
        tool_name=tool,
        tool_params={},
        tool_result_summary="",
        decision="ALLOW",
        decision_reason="",
        decision_engine="rule",
        start_time=now,
        end_time=now,
    )


class TestMerkleChain:
    def test_hash_is_deterministic(self):
        chain1 = MerkleChain()
        chain2 = MerkleChain()
        span = _make_span()
        assert chain1.compute_hash(span) == chain2.compute_hash(span)

    def test_hash_changes_with_content(self):
        chain = MerkleChain()
        span1 = _make_span(tool="tool_a")
        span2 = _make_span(tool="tool_b")
        hash1 = chain.compute_hash(span1)
        chain.reset()
        hash2 = chain.compute_hash(span2)
        assert hash1 != hash2

    def test_chain_links_hashes(self):
        chain = MerkleChain()
        span1 = _make_span(span_id="s1")
        span2 = _make_span(span_id="s2")
        hash1 = chain.compute_hash(span1)
        hash2 = chain.compute_hash(span2)
        assert hash1 != hash2  # Second hash includes first

    def test_verify_chain_valid(self):
        chain = MerkleChain()
        spans = []
        for i in range(5):
            span = _make_span(span_id=f"s{i}")
            span.merkle_hash = chain.compute_hash(span)
            spans.append(span)
        assert MerkleChain.verify_chain(spans)

    def test_verify_chain_detects_tampering(self):
        chain = MerkleChain()
        spans = []
        for i in range(5):
            span = _make_span(span_id=f"s{i}")
            span.merkle_hash = chain.compute_hash(span)
            spans.append(span)

        # Tamper with a span
        spans[2].decision = "BLOCK"
        assert not MerkleChain.verify_chain(spans)

    def test_verify_chain_detects_deletion(self):
        chain = MerkleChain()
        spans = []
        for i in range(5):
            span = _make_span(span_id=f"s{i}")
            span.merkle_hash = chain.compute_hash(span)
            spans.append(span)

        # Delete middle span
        del spans[2]
        assert not MerkleChain.verify_chain(spans)

    def test_empty_chain_verifies(self):
        assert MerkleChain.verify_chain([])
