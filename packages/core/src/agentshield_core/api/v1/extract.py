"""POST /api/v1/extract — Two-phase extraction endpoint."""

from __future__ import annotations

from pydantic import BaseModel
from fastapi import APIRouter, Depends, HTTPException

from agentshield_core.dependencies import get_schema_registry, get_two_phase_engine
from agentshield_core.engine.two_phase import TwoPhaseEngine
from agentshield_core.schemas.registry import SchemaRegistry

router = APIRouter()


class ExtractRequest(BaseModel):
    data: str
    schema_name: str  # e.g., "email", "web_page", "support_ticket"


class ExtractResponse(BaseModel):
    extracted: dict
    schema_name: str


@router.post("/extract", response_model=ExtractResponse)
async def extract_data(
    request: ExtractRequest,
    engine: TwoPhaseEngine = Depends(get_two_phase_engine),
) -> ExtractResponse:
    try:
        extracted = await engine.phase1_extract(request.data, request.schema_name)
    except KeyError:
        raise HTTPException(
            status_code=422,
            detail=f"Unknown schema: '{request.schema_name}'. Available: email, web_page, support_ticket",
        )
    except Exception as e:
        raise HTTPException(status_code=422, detail=str(e))
    return ExtractResponse(
        extracted=extracted,
        schema_name=request.schema_name,
    )


@router.get("/schemas")
async def list_schemas(
    registry: SchemaRegistry = Depends(get_schema_registry),
) -> dict:
    """List available extraction schemas."""
    types = registry.list_types()
    return {
        "schemas": types,
        "total": len(types),
    }
