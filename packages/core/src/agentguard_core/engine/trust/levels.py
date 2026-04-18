"""Trust level definitions and source mapping."""

from __future__ import annotations

import enum


class TrustLevel(enum.IntEnum):
    """Trust levels ordered from most to least trusted."""

    TRUSTED = 5  # System instructions (system prompt, developer config)
    VERIFIED = 4  # Authenticated user direct input
    INTERNAL = 3  # Internal systems / other Agent data (trust downgrade)
    EXTERNAL = 2  # External sources (email, web, documents)
    UNTRUSTED = 1  # Known high-risk or unsanitized data


# Server-side source → trust level mapping
# Client-claimed levels can only downgrade from these, never upgrade
TRUST_SOURCE_MAPPING: dict[str, TrustLevel] = {
    "system": TrustLevel.TRUSTED,
    "user_input": TrustLevel.VERIFIED,
    "agent/*": TrustLevel.INTERNAL,
    "email/*": TrustLevel.EXTERNAL,
    "web/*": TrustLevel.EXTERNAL,
    "rag/*": TrustLevel.EXTERNAL,
    "api/*": TrustLevel.EXTERNAL,
    "file/*": TrustLevel.EXTERNAL,
    "unknown": TrustLevel.UNTRUSTED,
}
