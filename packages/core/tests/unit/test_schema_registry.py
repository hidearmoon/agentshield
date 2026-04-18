"""Tests for Schema Registry."""

import pytest
from agentguard_core.schemas.registry import SchemaRegistry


class TestSchemaRegistry:
    def test_create_default_has_builtins(self, schema_registry: SchemaRegistry):
        types = schema_registry.list_types()
        assert "email" in types
        assert "web_page" in types
        assert "support_ticket" in types

    def test_get_email_schema(self, schema_registry: SchemaRegistry):
        schema = schema_registry.get("email")
        assert "fields" in schema
        assert "from" in schema["fields"]
        assert "subject" in schema["fields"]

    def test_unknown_type_raises(self, schema_registry: SchemaRegistry):
        with pytest.raises(KeyError):
            schema_registry.get("nonexistent")

    def test_register_custom_schema(self):
        registry = SchemaRegistry()
        registry.register("custom", {"fields": {"data": {"type": "string"}}})
        assert registry.get("custom") == {"fields": {"data": {"type": "string"}}}

    def test_load_from_directory(self, tmp_path):
        """Load schemas from YAML files in a directory."""
        (tmp_path / "invoice.yaml").write_text("fields:\n  amount:\n    type: number\n  vendor:\n    type: string\n")
        registry = SchemaRegistry()
        registry.load_from_directory(tmp_path)
        schema = registry.get("invoice")
        assert "amount" in schema["fields"]
        assert "vendor" in schema["fields"]

    def test_list_types_empty(self):
        registry = SchemaRegistry()
        assert registry.list_types() == []

    def test_register_overwrites_existing(self):
        registry = SchemaRegistry()
        registry.register("test", {"v": 1})
        registry.register("test", {"v": 2})
        assert registry.get("test") == {"v": 2}
