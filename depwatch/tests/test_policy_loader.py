"""Tests for depwatch.policy_loader — loading rules from config dicts."""

from __future__ import annotations

from depwatch.policy_loader import load_rules


def test_returns_empty_when_no_policy_section():
    rules = load_rules({})
    assert rules == []


def test_returns_empty_when_rules_list_missing():
    rules = load_rules({"policy": {}})
    assert rules == []


def test_parses_single_rule():
    cfg = {
        "policy": {
            "rules": [
                {"name": "ci-gate", "max_vulnerabilities": 0, "min_severity": "high"}
            ]
        }
    }
    rules = load_rules(cfg)
    assert len(rules) == 1
    assert rules[0].name == "ci-gate"
    assert rules[0].max_vulnerabilities == 0
    assert rules[0].min_severity == "high"


def test_parses_multiple_rules():
    cfg = {
        "policy": {
            "rules": [
                {"name": "a", "max_outdated": 3},
                {"name": "b", "blocked_packages": ["pyyaml"]},
            ]
        }
    }
    rules = load_rules(cfg)
    assert len(rules) == 2
    assert rules[0].max_outdated == 3
    assert "pyyaml" in rules[1].blocked_packages


def test_defaults_for_missing_fields():
    cfg = {"policy": {"rules": [{"name": "minimal"}]}}
    rule = load_rules(cfg)[0]
    assert rule.max_outdated is None
    assert rule.max_vulnerabilities is None
    assert rule.min_severity is None
    assert rule.blocked_packages == []


def test_ignores_non_dict_entries():
    cfg = {"policy": {"rules": ["bad", None, {"name": "ok"}]}}
    rules = load_rules(cfg)
    assert len(rules) == 1
    assert rules[0].name == "ok"


def test_unnamed_rule_gets_default_name():
    cfg = {"policy": {"rules": [{}]}}
    rules = load_rules(cfg)
    assert rules[0].name == "unnamed"
