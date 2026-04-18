"""Tests that verify config YAML files are valid and consistent with code."""

from __future__ import annotations

from pathlib import Path

import yaml

from agentguard_core.engine.trust.levels import TrustLevel, TRUST_SOURCE_MAPPING
from agentguard_core.engine.intent.rule_engine import BUILTIN_RULES

CONFIGS_DIR = Path(__file__).parents[4] / "configs"


class TestConfigFiles:
    def test_default_policy_yaml_loads(self):
        path = CONFIGS_DIR / "default_policy.yaml"
        with open(path) as f:
            data = yaml.safe_load(f)
        assert "trust_policies" in data
        for level_name in data["trust_policies"]:
            assert level_name in TrustLevel.__members__, f"Unknown trust level: {level_name}"

    def test_trust_source_mapping_yaml_loads(self):
        path = CONFIGS_DIR / "trust_source_mapping.yaml"
        with open(path) as f:
            data = yaml.safe_load(f)
        assert "trust_sources" in data
        for entry in data["trust_sources"]:
            assert "source" in entry
            assert "trust_level" in entry
            assert entry["trust_level"] in TrustLevel.__members__

    def test_trust_source_mapping_matches_code(self):
        """YAML sources should match the hardcoded TRUST_SOURCE_MAPPING."""
        path = CONFIGS_DIR / "trust_source_mapping.yaml"
        with open(path) as f:
            data = yaml.safe_load(f)
        yaml_sources = {e["source"] for e in data["trust_sources"]}
        code_sources = set(TRUST_SOURCE_MAPPING.keys())
        # All code sources should be in YAML
        assert code_sources == yaml_sources, (
            f"Mismatch: in code but not yaml: {code_sources - yaml_sources}, "
            f"in yaml but not code: {yaml_sources - code_sources}"
        )

    def test_builtin_rules_yaml_loads(self):
        path = CONFIGS_DIR / "builtin_rules.yaml"
        with open(path) as f:
            data = yaml.safe_load(f)
        assert "rules" in data
        yaml_rule_names = {r["name"] for r in data["rules"]}
        code_rule_names = {r.name for r in BUILTIN_RULES}
        assert yaml_rule_names == code_rule_names, (
            f"Mismatch: in code but not yaml: {code_rule_names - yaml_rule_names}, "
            f"in yaml but not code: {yaml_rule_names - code_rule_names}"
        )

    def test_all_yaml_rules_have_descriptions(self):
        path = CONFIGS_DIR / "builtin_rules.yaml"
        with open(path) as f:
            data = yaml.safe_load(f)
        for rule in data["rules"]:
            assert "description" in rule, f"Rule '{rule['name']}' missing description"
            assert len(rule["description"]) > 0

    def test_default_policy_trust_levels_complete(self):
        """All 5 trust levels should have policies defined."""
        path = CONFIGS_DIR / "default_policy.yaml"
        with open(path) as f:
            data = yaml.safe_load(f)
        for level in TrustLevel:
            assert level.name in data["trust_policies"], f"Trust level {level.name} missing from default_policy.yaml"
