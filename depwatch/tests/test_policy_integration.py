"""Integration test: load policy from TOML-like dict and evaluate a scan."""

from __future__ import annotations

from depwatch.checker import CheckResult
from depwatch.cve import CVEResult, Vulnerability
from depwatch.policy import evaluate
from depwatch.policy_loader import load_rules
from depwatch.scanner import ScanReport


def _vuln(cve_id: str = "CVE-2024-0001", severity: str = "critical") -> Vulnerability:
    return Vulnerability(cve_id=cve_id, summary="Remote code execution", severity=severity)


def _result(package: str, installed: str, latest: str | None, vulns=None) -> CheckResult:
    cve = CVEResult(package=package, vulnerabilities=vulns or [])
    return CheckResult(package=package, installed=installed, latest=latest, cve_result=cve)


CONFIG = {
    "policy": {
        "rules": [
            {
                "name": "ci-gate",
                "max_vulnerabilities": 0,
                "min_severity": "high",
                "blocked_packages": ["insecure-lib"],
            },
            {
                "name": "drift-check",
                "max_outdated": 2,
            },
        ]
    }
}


def test_clean_report_passes_all_rules():
    report = ScanReport(results=[
        _result("requests", "2.31.0", None, vulns=[]),
    ])
    rules = load_rules(CONFIG)
    result = evaluate(report, rules)
    assert result.passed


def test_critical_vuln_triggers_ci_gate():
    report = ScanReport(results=[
        _result("requests", "2.0.0", "2.31.0", vulns=[_vuln(severity="critical")]),
    ])
    rules = load_rules(CONFIG)
    result = evaluate(report, rules)
    assert not result.passed
    names = [v.rule_name for v in result.violations]
    assert "ci-gate" in names


def test_blocked_package_triggers_ci_gate():
    report = ScanReport(results=[
        _result("insecure-lib", "1.0.0", None, vulns=[]),
    ])
    rules = load_rules(CONFIG)
    result = evaluate(report, rules)
    assert not result.passed
    assert any(v.rule_name == "ci-gate" for v in result.violations)


def test_too_many_outdated_triggers_drift_check():
    report = ScanReport(results=[
        _result("a", "1.0", "2.0"),
        _result("b", "1.0", "2.0"),
        _result("c", "1.0", "2.0"),
    ])
    rules = load_rules(CONFIG)
    result = evaluate(report, rules)
    assert not result.passed
    assert any(v.rule_name == "drift-check" for v in result.violations)


def test_multiple_violations_all_reported():
    report = ScanReport(results=[
        _result("insecure-lib", "1.0", "2.0", vulns=[_vuln()]),
        _result("b", "1.0", "2.0"),
        _result("c", "1.0", "2.0"),
    ])
    rules = load_rules(CONFIG)
    result = evaluate(report, rules)
    assert not result.passed
    rule_names = {v.rule_name for v in result.violations}
    assert "ci-gate" in rule_names
    assert "drift-check" in rule_names
