"""Console-specific configuration via environment variables."""

from __future__ import annotations

from pydantic_settings import BaseSettings, SettingsConfigDict


class ConsoleSettings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="AGENTGUARD_CONSOLE_")

    # Server
    host: str = "0.0.0.0"
    port: int = 8100
    debug: bool = False

    # PostgreSQL (shared with core)
    database_url: str = "postgresql+asyncpg://agentguard:dev-password@localhost:5432/agentguard"

    # ClickHouse (shared with core)
    clickhouse_host: str = "localhost"
    clickhouse_port: int = 8123
    clickhouse_database: str = "agentguard"

    # JWT
    jwt_secret: str = "change-me-in-production"
    jwt_algorithm: str = "HS256"
    jwt_expire_minutes: int = 720  # 12 hours

    # CORS
    cors_origins: list[str] = ["http://localhost:5173", "http://localhost:3000"]

    # Core API base URL (for proxying / simulation calls)
    core_api_url: str = "http://localhost:8000"


settings = ConsoleSettings()
