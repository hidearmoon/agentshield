"""Stage 1: Format cleansing — remove hidden chars, decode encodings with depth limit."""

from __future__ import annotations

import base64
import hashlib
import html
import logging
import re
from urllib.parse import unquote

from agentshield_core.config import settings
from agentshield_core.engine.sanitization.base import SanitizationStage

logger = logging.getLogger(__name__)


class FormatCleansingStage(SanitizationStage):
    """
    Stage 1: Format cleansing.
    - Remove zero-width and invisible Unicode characters
    - Remove hidden HTML elements
    - Iteratively decode base64/HTML entities with max_depth limit
    - Detect and break circular encoding
    """

    name = "format_cleansing"

    async def process(self, data: str) -> str:
        original_len = len(data)

        # Step 1: Iterative decode with depth limit and cycle detection
        data = self._iterative_decode(data)

        # Step 2: Remove zero-width characters
        data = re.sub(r"[\u200b\u200c\u200d\ufeff\u00ad]", "", data)

        # Step 3: Remove invisible Unicode control characters
        data = re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\x9f]", "", data)

        # Step 3b: Remove Unicode bidirectional override/embedding characters
        # These can visually reorder text to hide instructions
        data = re.sub(r"[\u200e\u200f\u202a-\u202e\u2066-\u2069]", "", data)

        # Step 4: Remove hidden HTML elements
        data = self._remove_hidden_html(data)

        # Track how much content was removed (useful for threat metrics)
        removed = max(0, original_len - len(data))
        self._last_removed_bytes = removed

        if removed > 0:
            logger.info(
                "format_cleansing: removed %d bytes (%d%% of input)",
                removed,
                int(removed / original_len * 100) if original_len else 0,
            )

        return data

    def _iterative_decode(self, data: str) -> str:
        """
        Iteratively decode base64 and HTML entities.
        Max depth = settings.max_decode_depth (default 3).
        Stops on cycle detection (content hash seen before).
        """
        seen_hashes: set[str] = set()

        for _ in range(settings.max_decode_depth):
            content_hash = hashlib.sha256(data.encode()).hexdigest()
            if content_hash in seen_hashes:
                break  # Cycle detected
            seen_hashes.add(content_hash)

            # HTML entity decode
            decoded = html.unescape(data)
            # URL percent decode (catches %XX encoded instructions)
            if "%" in decoded:
                decoded = unquote(decoded)
            # Base64 segment decode
            decoded = self._decode_base64_segments(decoded)

            if decoded == data:
                break  # No more changes
            data = decoded

        return data

    @staticmethod
    def _decode_base64_segments(data: str) -> str:
        """Find and decode base64-encoded segments in the text."""
        # Skip processing if input is too large (prevents memory exhaustion)
        if len(data) > 1_000_000:
            return data

        def _try_decode(match: re.Match) -> str:
            segment = match.group(0)
            try:
                decoded = base64.b64decode(segment).decode("utf-8", errors="ignore")
                # Only replace if decoded result looks like text
                if decoded.isprintable() or any(c.isalpha() for c in decoded):
                    return decoded
            except Exception:
                pass
            return segment

        # Match potential base64 strings (min 20 chars, valid base64 charset)
        pattern = r"[A-Za-z0-9+/]{20,}={0,2}"
        return re.sub(pattern, _try_decode, data)

    @staticmethod
    def _remove_hidden_html(data: str) -> str:
        """Remove HTML elements that are visually hidden."""
        # Remove elements with display:none
        data = re.sub(
            r"<[^>]+style\s*=\s*[\"'][^\"']*display\s*:\s*none[^\"']*[\"'][^>]*>.*?</[^>]+>",
            "",
            data,
            flags=re.IGNORECASE | re.DOTALL,
        )
        # Remove elements with visibility:hidden
        data = re.sub(
            r"<[^>]+style\s*=\s*[\"'][^\"']*visibility\s*:\s*hidden[^\"']*[\"'][^>]*>.*?</[^>]+>",
            "",
            data,
            flags=re.IGNORECASE | re.DOTALL,
        )
        # Remove zero-size elements (width:0 or height:0)
        data = re.sub(
            r"<[^>]+style\s*=\s*[\"'][^\"']*(?:width|height)\s*:\s*0[^\"']*[\"'][^>]*>.*?</[^>]+>",
            "",
            data,
            flags=re.IGNORECASE | re.DOTALL,
        )
        # Remove offscreen positioned elements (left/top/text-indent with large negative values)
        data = re.sub(
            r"<[^>]+style\s*=\s*[\"'][^\"']*(?:left|top|text-indent)\s*:\s*-\d{4,}px[^\"']*[\"'][^>]*>.*?</[^>]+>",
            "",
            data,
            flags=re.IGNORECASE | re.DOTALL,
        )
        # Remove elements with clip-path:inset(100%)
        data = re.sub(
            r"<[^>]+style\s*=\s*[\"'][^\"']*clip-path\s*:\s*inset\s*\(100%\)[^\"']*[\"'][^>]*>.*?</[^>]+>",
            "",
            data,
            flags=re.IGNORECASE | re.DOTALL,
        )
        # Remove elements with opacity:0 or font-size:0
        data = re.sub(
            r"<[^>]+style\s*=\s*[\"'][^\"']*(?:opacity\s*:\s*0|font-size\s*:\s*0)[^\"']*[\"'][^>]*>.*?</[^>]+>",
            "",
            data,
            flags=re.IGNORECASE | re.DOTALL,
        )
        # Remove elements with max-height:0 and overflow:hidden
        data = re.sub(
            r"<[^>]+style\s*=\s*[\"'][^\"']*max-height\s*:\s*0[^\"']*overflow\s*:\s*hidden[^\"']*[\"'][^>]*>.*?</[^>]+>",
            "",
            data,
            flags=re.IGNORECASE | re.DOTALL,
        )
        # Remove <style> tags entirely (CSS class definitions can hide content)
        data = re.sub(r"<style[^>]*>.*?</style>", "", data, flags=re.IGNORECASE | re.DOTALL)
        # Remove <script> tags entirely
        data = re.sub(r"<script[^>]*>.*?</script>", "", data, flags=re.IGNORECASE | re.DOTALL)
        # Remove HTML comments — use greedy match to catch nested comments
        # e.g., "<!-- outer <!-- inner --> evil() -->" is fully removed
        data = re.sub(r"<!--.*-->", "", data, flags=re.DOTALL)
        return data
