"""Tests for depwatch.policy — rule evaluation logic."""

from __future__ import annotations

import pytest

from depwatch.checker import CheckResult
from depwatch.cve import CVEResult, Vulnerability
from depwatch.scanner import ScanReport
from depwatch.policy import PolicyRule, evaluate


def _vuln(cve_id: str = "CVE-2024-1234", severity: str = "high") -> Vulnerability:
    return Vulnerability(cve_id=cve_id, summary="test", severity=severity)


def _result(
    package: str = "requests",
    installed: str = "2.0.0",
    latest: str | None = "2.1.0",
    vulns: list | None = None,
) -> CheckResult:
    cve = CVEResult(package=package, vulnerabilities=vulns or [])
    return CheckResult(package=package, installed=installed, latest=latest, cve_result=cve)


def _report(*results: CheckResult) -> ScanReport:
    return ScanReport(results=list(results))


# --- max_outdated ---

def test_passes_when_outdated_within_limit():
    report = _report(_result(latest="2.1.0"))
    rule = PolicyRule(name="r", max_outdated=5)
    assert evaluate(report, [rule]).passed


def test_fails_when_outdated_exceeds_limit():
    report = _report(_result(latest="2.1.0"), _result("flask", "1.0", "2.0"))
    rule = PolicyRule(name="r", max_outdated=1)
    result = evaluate(report, [rule])
    assert not result.passed
    assert any("Outdated" in v.message for v in result.violations)


# --- max_vulnerabilities ---

def test_passes_when_vulns_within_limit():
    report = _report(_result(vulns=[_vuln()]))
    rule = PolicyRule(name="r", max_vulnerabilities=2)
    assert evaluate(report, [rule]).passed


def test_fails_when_vulns_exceed_limit():
    report = _report(_result(vulns=[_vuln()]), _result("flask", vulns=[_vuln("CVE-2024-9999")]))
    rule = PolicyRule(name="r", max_vulnerabilities=0)
    result = evaluate(report, [rule])
    assert not result.passed
    assert any("Vulnerable" in v.message for v in result.violations)


# --- min_severity ---

def test_fails_on_critical_when_threshold_is_high():
    report = _report(_result(vulns=[_vuln(severity="critical")]))
    rule = PolicyRule(name="r", min_severity="high")
    result = evaluate(report, [rule])
    assert not result.passed
    assert any("CRITICAL" in v.message for v in result.violations)


def test_passes_when_severity_below_threshold():
    report = _report(_result(vulns=[_vuln(severity="low")]))
    rule = PolicyRule(name="r", min_severity="high")
    assert evaluate(report, [rule]).passed


# --- blocked_packages ---

def test_fails_when_blocked_package_present():
    report = _report(_result(package="pyyaml", latest=None))
    rule = PolicyRule(name="r", blocked_packages=["pyyaml"])
    result = evaluate(report, [rule])
    assert not result.passed
    assert any("pyyaml" in v.message for v in result.violations)


def test_passes_when_blocked_package_absent():
    report = _report(_result(package="requests", latest=None))
    rule = PolicyRule(name="r", blocked_packages=["pyyaml"])
    assert evaluate(report, [rule]).passed


# --- summary ---

def test_summary_passed():
    report = _report(_result(latest=None, vulns=[]))
    result = evaluate(report, [])
    assert "passed" in result.summary()


def test_summary_failed_contains_violation_count():
    report = _report(_result(vulns=[_vuln()]))
    rule = PolicyRule(name="ci", max_vulnerabilities=0)
    result = evaluate(report, [rule])
    assert "FAILED" in result.summary()
    assert "ci" in result.summary()
