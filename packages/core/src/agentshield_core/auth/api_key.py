"""API key validation middleware."""

from __future__ import annotations

import hashlib

from fastapi import HTTPException, Security
from fastapi.security import APIKeyHeader


api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)


def hash_api_key(key: str) -> str:
    return hashlib.sha256(key.encode()).hexdigest()


async def validate_api_key(
    api_key: str | None = Security(api_key_header),
) -> str:
    """Validate API key and return key prefix for identification."""
    if not api_key:
        raise HTTPException(status_code=401, detail="API key required")

    # In production, this hashes the key and queries the database:
    # key_hash = hash_api_key(api_key)
    # db_key = await db.execute(select(ApiKey).where(ApiKey.key_hash == key_hash))
    return api_key[:8]
