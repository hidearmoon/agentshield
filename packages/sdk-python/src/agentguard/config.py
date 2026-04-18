"""Configuration loader for AgentGuard SDK.

Configuration is resolved in order:
1. Explicit kwargs passed to Shield()
2. Environment variables (AGENTGUARD_*)
3. agentguard.yaml in the current working directory
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

import yaml

from agentguard.exceptions import ConfigError

_DEFAULT_BASE_URL = "http://localhost:8000"
_CONFIG_FILENAME = "agentguard.yaml"


@dataclass(frozen=True)
class ShieldConfig:
    """Resolved SDK configuration."""

    api_key: str
    base_url: str = _DEFAULT_BASE_URL
    timeout: float = 10.0
    max_retries: int = 3
    agent_id: str = ""
    confirm_callback: object | None = None


def _load_yaml_config() -> dict:
    """Load agentguard.yaml from CWD if it exists."""
    config_path = Path.cwd() / _CONFIG_FILENAME
    if not config_path.is_file():
        return {}
    with config_path.open() as f:
        data = yaml.safe_load(f)
    return data if isinstance(data, dict) else {}


def resolve_config(
    *,
    api_key: str | None = None,
    base_url: str | None = None,
    timeout: float | None = None,
    max_retries: int | None = None,
    agent_id: str | None = None,
    confirm_callback: object | None = None,
) -> ShieldConfig:
    """Resolve configuration from kwargs, env vars, and YAML file.

    The API key MUST come from the AGENTGUARD_API_KEY env var or be passed
    explicitly. It is never read from the YAML file (secrets should not live
    in config files that may be committed to version control).
    """
    yaml_cfg = _load_yaml_config()

    resolved_api_key = api_key or os.environ.get("AGENTGUARD_API_KEY", "")
    if not resolved_api_key:
        raise ConfigError(
            "API key is required. Set the AGENTGUARD_API_KEY environment variable or pass api_key= to Shield()."
        )

    resolved_base_url = (
        base_url or os.environ.get("AGENTGUARD_BASE_URL") or yaml_cfg.get("base_url") or _DEFAULT_BASE_URL
    )

    resolved_timeout = (
        timeout if timeout is not None else float(os.environ.get("AGENTGUARD_TIMEOUT", yaml_cfg.get("timeout", 10.0)))
    )

    resolved_max_retries = (
        max_retries
        if max_retries is not None
        else int(os.environ.get("AGENTGUARD_MAX_RETRIES", yaml_cfg.get("max_retries", 3)))
    )

    resolved_agent_id = agent_id or os.environ.get("AGENTGUARD_AGENT_ID") or yaml_cfg.get("agent_id", "")

    return ShieldConfig(
        api_key=resolved_api_key,
        base_url=resolved_base_url.rstrip("/"),
        timeout=resolved_timeout,
        max_retries=resolved_max_retries,
        agent_id=resolved_agent_id,
        confirm_callback=confirm_callback,
    )
