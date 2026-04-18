"""Base class for sanitization stages."""

from __future__ import annotations

from abc import ABC, abstractmethod


class SanitizationStage(ABC):
    """Abstract base class for data sanitization pipeline stages."""

    name: str = "base"

    def should_apply(self, source_id: str) -> bool:
        """Override to conditionally apply this stage based on data source."""
        return True

    @abstractmethod
    async def process(self, data: str) -> str:
        """Process data through this sanitization stage."""
        ...
