"""HTTP client for the AgentShield core API."""

from __future__ import annotations

from typing import Any

import httpx

from agentshield.config import ShieldConfig
from agentshield.exceptions import ServerError
from agentshield.models import (
    CheckResult,
    Decision,
    ExtractedData,
    MarkedData,
    SanitizedData,
    SessionInfo,
)

_SDK_VERSION = "0.1.0"


class ServerClient:
    """Async HTTP client that forwards requests to the AgentShield core engine."""

    def __init__(self, config: ShieldConfig) -> None:
        self._config = config
        transport = httpx.AsyncHTTPTransport(retries=config.max_retries)
        self._http = httpx.AsyncClient(
            base_url=config.base_url,
            timeout=httpx.Timeout(config.timeout),
            transport=transport,
            headers={
                "Authorization": f"Bearer {config.api_key}",
                "User-Agent": f"agentshield-python/{_SDK_VERSION}",
                "Content-Type": "application/json",
            },
        )

    async def _request(self, method: str, path: str, **kwargs: Any) -> httpx.Response:
        """Send an HTTP request with error wrapping."""
        try:
            resp = await self._http.request(method, path, **kwargs)
        except httpx.TimeoutException as exc:
            raise ServerError(f"AgentShield server timed out ({self._config.base_url}): {exc}") from exc
        except httpx.ConnectError as exc:
            raise ServerError(f"Cannot connect to AgentShield server ({self._config.base_url}): {exc}") from exc
        except httpx.HTTPError as exc:
            raise ServerError(f"HTTP error: {exc}") from exc

        if resp.status_code >= 500:
            raise ServerError(
                f"AgentShield server error: {resp.status_code} {resp.text[:200]}",
                status_code=resp.status_code,
            )
        if resp.status_code >= 400:
            is_json = resp.headers.get("content-type", "").startswith("application/json")
            detail = resp.json().get("detail", resp.text[:200]) if is_json else resp.text[:200]
            raise ServerError(
                f"AgentShield request failed ({resp.status_code}): {detail}",
                status_code=resp.status_code,
            )
        return resp

    async def check_tool_call(
        self,
        *,
        session_id: str,
        tool_name: str,
        params: dict,
        source_id: str = "",
        client_trust_level: str | None = None,
    ) -> CheckResult:
        """POST /api/v1/check — ask the server whether a tool call is allowed."""
        payload: dict = {
            "session_id": session_id,
            "tool_name": tool_name,
            "params": params,
            "sdk_version": _SDK_VERSION,
            "source_id": source_id,
        }
        if client_trust_level is not None:
            payload["client_trust_level"] = client_trust_level

        resp = await self._request("POST", "/api/v1/check", json=payload)
        data = resp.json()
        return CheckResult(
            action=Decision(data["action"]),
            reason=data.get("reason", ""),
            trace_id=data.get("trace_id", ""),
            span_id=data.get("span_id", ""),
        )

    async def sanitize(
        self,
        *,
        data: str,
        source: str,
        data_type: str = "auto",
    ) -> SanitizedData:
        """POST /api/v1/sanitize — sanitize untrusted data server-side."""
        resp = await self._request(
            "POST",
            "/api/v1/sanitize",
            json={"data": data, "source": source, "data_type": data_type},
        )

        body = resp.json()
        return SanitizedData(
            content=body["content"],
            trust_level=body["trust_level"],
            sanitization_chain=body.get("sanitization_chain", []),
        )

    async def extract(
        self,
        *,
        data: str,
        schema_name: str,
    ) -> ExtractedData:
        """POST /api/v1/extract — two-phase structured extraction."""
        resp = await self._request(
            "POST",
            "/api/v1/extract",
            json={"data": data, "schema_name": schema_name},
        )

        body = resp.json()
        return ExtractedData(
            extracted=body["extracted"],
            schema_name=body["schema_name"],
        )

    async def create_session(
        self,
        *,
        user_message: str,
        agent_id: str = "",
        metadata: dict | None = None,
    ) -> SessionInfo:
        """POST /api/v1/sessions — create a new guarded session."""
        resp = await self._request(
            "POST",
            "/api/v1/sessions",
            json={
                "user_message": user_message,
                "agent_id": agent_id,
                "metadata": metadata or {},
            },
        )

        body = resp.json()
        return SessionInfo(
            session_id=body["session_id"],
            trace_id=body["trace_id"],
        )

    async def mark_data(
        self,
        *,
        data: str,
        source_id: str,
        client_trust_level: str | None = None,
    ) -> MarkedData:
        """POST /api/v1/mark — annotate data with trust metadata."""
        payload: dict = {"data": data, "source_id": source_id}
        if client_trust_level is not None:
            payload["client_trust_level"] = client_trust_level

        resp = await self._request("POST", "/api/v1/mark", json=payload)

        body = resp.json()
        return MarkedData(
            content=body["content"],
            trust_level=body["trust_level"],
            source_id=body["source_id"],
            allowed_actions=body.get("allowed_actions", []),
            tool_restrictions=body.get("tool_restrictions", []),
        )

    async def close(self) -> None:
        """Close the underlying HTTP client."""
        await self._http.aclose()
