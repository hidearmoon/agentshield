"""Schema registry for two-phase extraction."""

from __future__ import annotations

from pathlib import Path

import yaml


class SchemaRegistry:
    """Registry of extraction schemas for different data types."""

    def __init__(self) -> None:
        self._schemas: dict[str, dict] = {}

    def register(self, data_type: str, schema: dict) -> None:
        self._schemas[data_type] = schema

    def get(self, data_type: str) -> dict:
        if data_type not in self._schemas:
            raise KeyError(f"Unknown data type: {data_type}")
        return self._schemas[data_type]

    def list_types(self) -> list[str]:
        return list(self._schemas.keys())

    def load_from_directory(self, directory: str | Path) -> None:
        """Load all YAML schema files from a directory."""
        path = Path(directory)
        for yaml_file in path.glob("*.yaml"):
            data_type = yaml_file.stem
            with open(yaml_file) as f:
                schema = yaml.safe_load(f)
            self._schemas[data_type] = schema

    @classmethod
    def create_default(cls) -> SchemaRegistry:
        """Create registry with built-in schemas."""
        registry = cls()
        builtin_dir = Path(__file__).parent / "builtin"
        if builtin_dir.exists():
            registry.load_from_directory(builtin_dir)
        else:
            # Fallback: register hardcoded defaults
            registry.register("email", BUILTIN_EMAIL_SCHEMA)
            registry.register("web_page", BUILTIN_WEB_PAGE_SCHEMA)
            registry.register("support_ticket", BUILTIN_SUPPORT_TICKET_SCHEMA)
        return registry


BUILTIN_EMAIL_SCHEMA = {
    "fields": {
        "from": {"type": "string", "description": "Sender address"},
        "to": {"type": "string", "description": "Recipient address"},
        "subject": {"type": "string", "description": "Email subject"},
        "summary": {"type": "string", "max_length": 500, "description": "Content summary"},
        "action_items": {"type": "array", "items": "string", "description": "Action items"},
        "attachments": {"type": "array", "items": {"name": "string", "type": "string"}},
    }
}

BUILTIN_WEB_PAGE_SCHEMA = {
    "fields": {
        "title": {"type": "string"},
        "main_content": {"type": "string", "max_length": 2000},
        "links": {"type": "array", "items": {"text": "string", "url": "string"}},
        "structured_data": {"type": "object"},
    }
}

BUILTIN_SUPPORT_TICKET_SCHEMA = {
    "fields": {
        "ticket_id": {"type": "string"},
        "customer": {"type": "string"},
        "issue_category": {"type": "string", "enum": ["billing", "technical", "account", "other"]},
        "description": {"type": "string", "max_length": 1000},
        "priority": {"type": "string", "enum": ["low", "medium", "high", "critical"]},
    }
}
