"""Proxy configuration via environment variables."""

from __future__ import annotations

from pydantic_settings import BaseSettings, SettingsConfigDict


class ProxySettings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="AGENTGUARD_PROXY_")

    # Core engine the proxy delegates security checks to
    core_engine_url: str = "http://localhost:8000"

    # Default upstream tool service base URL
    upstream_url: str = "http://localhost:9000"

    # Proxy server bind settings
    host: str = "0.0.0.0"
    port: int = 8080

    # Rate limiter defaults
    rate_limit_tokens: float = 60.0  # bucket capacity per agent
    rate_limit_refill: float = 10.0  # tokens added per second

    # Timeouts (seconds)
    core_timeout: float = 5.0
    upstream_timeout: float = 30.0

    # Degraded mode: allow requests when core engine is unreachable
    allow_degraded_mode: bool = False


settings = ProxySettings()
