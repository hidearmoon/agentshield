"""Application configuration via environment variables."""

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="AGENTSHIELD_")

    # Server
    host: str = "0.0.0.0"
    port: int = 8000
    debug: bool = False

    # PostgreSQL
    database_url: str = "postgresql+asyncpg://agentshield:dev-password@localhost:5432/agentshield"

    # ClickHouse
    clickhouse_host: str = "localhost"
    clickhouse_port: int = 8123
    clickhouse_database: str = "agentshield"

    # LLM
    llm_provider: str = "openai"  # openai | anthropic | local
    openai_api_key: str = ""
    anthropic_api_key: str = ""
    llm_model: str = "gpt-4o-mini"

    # Security
    policy_signing_key: str = ""  # Ed25519 private key (base64)
    policy_verify_key: str = ""  # Ed25519 public key (base64)

    # Authentication
    require_api_key: bool = False  # Enable in production
    api_key_header: str = "X-API-Key"

    # Detection thresholds
    suspicious_threshold: float = 0.6
    anomaly_threshold: float = 0.85

    # Sanitization
    max_decode_depth: int = 3


settings = Settings()
