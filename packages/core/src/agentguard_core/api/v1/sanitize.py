"""POST /api/v1/sanitize — Data sanitization endpoint."""

from __future__ import annotations

from pydantic import BaseModel
from fastapi import APIRouter, Depends

from agentguard_core.dependencies import get_sanitization_pipeline
from agentguard_core.engine.sanitization.pipeline import DataSanitizationPipeline

router = APIRouter()


class SanitizeRequest(BaseModel):
    data: str
    source: str
    data_type: str = "auto"


class SanitizeResponse(BaseModel):
    content: str
    trust_level: str
    sanitization_chain: list[str]
    content_removed_bytes: int = 0


@router.post("/sanitize", response_model=SanitizeResponse)
async def sanitize_data(
    request: SanitizeRequest,
    pipeline: DataSanitizationPipeline = Depends(get_sanitization_pipeline),
) -> SanitizeResponse:
    result = await pipeline.process(request.data, source_id=request.source)
    return SanitizeResponse(
        content=result.content,
        trust_level=result.trust_level.name,
        sanitization_chain=result.sanitization_chain,
        content_removed_bytes=result.content_removed_bytes,
    )
