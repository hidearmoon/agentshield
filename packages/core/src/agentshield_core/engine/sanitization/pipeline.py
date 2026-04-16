"""Data sanitization pipeline orchestrator."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone

from agentshield_core.engine.sanitization.base import SanitizationStage
from agentshield_core.engine.trust.levels import TrustLevel
from agentshield_core.engine.trust.marker import TrustMarker


@dataclass
class SanitizedData:
    content: str
    trust_level: TrustLevel
    source_id: str
    sanitization_chain: list[str] = field(default_factory=list)
    original_hash: str = ""
    content_removed_bytes: int = 0
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


class DataSanitizationPipeline:
    """
    Data sanitization pipeline.
    Runs external data through ordered stages to neutralize injection attempts
    while preserving information content.
    """

    def __init__(
        self,
        stages: list[SanitizationStage],
        trust_marker: TrustMarker | None = None,
    ):
        self._stages = stages
        self._trust_marker = trust_marker or TrustMarker()

    async def process(self, raw_data: str, source_id: str = "unknown") -> SanitizedData:
        import hashlib

        data = raw_data
        applied_stages: list[str] = []

        for stage in self._stages:
            if stage.should_apply(source_id):
                data = await stage.process(data)
                applied_stages.append(stage.name)

        # Compute trust level server-side
        trust_level = self._trust_marker.compute_trust_level(source_id)

        removed = max(0, len(raw_data) - len(data))

        return SanitizedData(
            content=data,
            trust_level=trust_level,
            source_id=source_id,
            sanitization_chain=applied_stages,
            original_hash=hashlib.sha256(raw_data.encode()).hexdigest(),
            content_removed_bytes=removed,
        )
