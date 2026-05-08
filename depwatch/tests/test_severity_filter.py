"""Tests for depwatch.severity_filter."""

from __future__ import annotations

import pytest

from depwatch.cve import Vulnerability, CVEResult
from depwatch.checker import CheckResult
from depwatch.scanner import ScanReport
from depwatch.severity_filter import (
    _severity_rank,
    filter_vulnerabilities,
    filter_report,
)


def _vuln(severity: str) -> Vulnerability:
    return Vulnerability(id=f"CVE-2024-{severity}", severity=severity, description="test")


def _make_result(package: str, *severities: str) -> CheckResult:
    vulns = [_vuln(s) for s in severities]
    cve_result = CVEResult(package=package, version="1.0.0", vulnerabilities=vulns)
    return CheckResult(
        package=package,
        current_version="1.0.0",
        latest_version="2.0.0",
        cve_result=cve_result,
    )


# ---------------------------------------------------------------------------
# _severity_rank
# ---------------------------------------------------------------------------

def test_rank_critical_highest():
    assert _severity_rank("critical") > _severity_rank("high")


def test_rank_unknown_lowest():
    assert _severity_rank("unknown") == 0


def test_rank_case_insensitive():
    assert _severity_rank("HIGH") == _severity_rank("high")


def test_rank_unrecognised_returns_zero():
    assert _severity_rank("bogus") == 0


# ---------------------------------------------------------------------------
# filter_vulnerabilities
# ---------------------------------------------------------------------------

def test_filter_keeps_at_threshold():
    vulns = [_vuln("low"), _vuln("medium"), _vuln("high")]
    result = filter_vulnerabilities(vulns, "medium")
    assert len(result) == 2
    assert all(v.severity in ("medium", "high") for v in result)


def test_filter_critical_only():
    vulns = [_vuln("low"), _vuln("critical")]
    result = filter_vulnerabilities(vulns, "critical")
    assert len(result) == 1
    assert result[0].severity == "critical"


def test_filter_returns_all_when_threshold_is_unknown():
    vulns = [_vuln("low"), _vuln("medium")]
    result = filter_vulnerabilities(vulns, "unknown")
    assert len(result) == 2


def test_filter_returns_empty_when_none_qualify():
    vulns = [_vuln("low")]
    result = filter_vulnerabilities(vulns, "critical")
    assert result == []


# ---------------------------------------------------------------------------
# filter_report
# ---------------------------------------------------------------------------

def test_filter_report_removes_low_vulns():
    report = ScanReport(results=[
        _make_result("requests", "low", "high"),
        _make_result("flask", "low"),
    ])
    filtered = filter_report(report, "high")
    requests_result = next(r for r in filtered.results if r.package == "requests")
    flask_result = next(r for r in filtered.results if r.package == "flask")
    assert len(requests_result.cve_result.vulnerabilities) == 1
    assert len(flask_result.cve_result.vulnerabilities) == 0


def test_filter_report_package_no_longer_vulnerable_after_filter():
    report = ScanReport(results=[_make_result("boto3", "low")])
    filtered = filter_report(report, "high")
    assert filtered.vulnerable == []


def test_filter_report_preserves_result_count():
    report = ScanReport(results=[
        _make_result("a", "critical"),
        _make_result("b", "low"),
    ])
    filtered = filter_report(report, "medium")
    assert len(filtered.results) == 2


def test_filter_report_unchanged_when_all_above_threshold():
    report = ScanReport(results=[_make_result("django", "critical", "high")])
    filtered = filter_report(report, "low")
    assert len(filtered.results[0].cve_result.vulnerabilities) == 2
