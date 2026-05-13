"""Load PolicyRule definitions from the depwatch TOML config or a dict."""

from __future__ import annotations

from typing import Any, Dict, List

from depwatch.policy import PolicyRule


def _parse_rule(raw: Dict[str, Any]) -> PolicyRule:
    return PolicyRule(
        name=raw.get("name", "unnamed"),
        max_outdated=raw.get("max_outdated"),
        max_vulnerabilities=raw.get("max_vulnerabilities"),
        min_severity=raw.get("min_severity"),
        blocked_packages=raw.get("blocked_packages", []),
    )


def load_rules(config_dict: Dict[str, Any]) -> List[PolicyRule]:
    """Extract policy rules from a parsed TOML config dictionary.

    Expected shape::

        [[policy.rules]]
        name = "ci-gate"
        max_vulnerabilities = 0
        min_severity = "high"
    """
    policy_section = config_dict.get("policy", {})
    raw_rules = policy_section.get("rules", [])
    if not isinstance(raw_rules, list):
        return []
    return [_parse_rule(r) for r in raw_rules if isinstance(r, dict)]
