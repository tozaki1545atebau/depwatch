"""Tests for depwatch.diff."""

from __future__ import annotations

from unittest.mock import MagicMock

from depwatch.checker import CheckResult, PackageStatus
from depwatch.cve import CVEResult, Vulnerability
from depwatch.diff import compute
from depwatch.scanner import ScanReport


def _vuln(cve_id: str) -> Vulnerability:
    v = MagicMock(spec=Vulnerability)
    v.cve_id = cve_id
    return v


def _result(
    name: str,
    installed: str = "1.0.0",
    status: PackageStatus = PackageStatus.OK,
    cve_ids: list[str] | None = None,
) -> CheckResult:
    cve_result = MagicMock(spec=CVEResult)
    cve_result.vulnerabilities = [_vuln(c) for c in (cve_ids or [])]
    return CheckResult(
        package_name=name,
        installed_version=installed,
        latest_version=installed,
        status=status,
        cve_result=cve_result,
    )


def _report(*results: CheckResult) -> ScanReport:
    return ScanReport(results=list(results))


def test_empty_diff_when_identical() -> None:
    r = _result("flask", "2.0.0")
    diff = compute(_report(r), _report(r))
    assert diff.is_empty


def test_added_package_detected() -> None:
    prev = _report(_result("flask"))
    curr = _report(_result("flask"), _result("requests"))
    diff = compute(prev, curr)
    assert "requests" in diff.added
    assert diff.is_empty is False


def test_removed_package_detected() -> None:
    prev = _report(_result("flask"), _result("requests"))
    curr = _report(_result("flask"))
    diff = compute(prev, curr)
    assert "requests" in diff.removed


def test_version_change_detected() -> None:
    prev = _report(_result("flask", installed="2.0.0"))
    curr = _report(_result("flask", installed="2.1.0"))
    diff = compute(prev, curr)
    assert len(diff.changed) == 1
    assert diff.changed[0].previous_version == "2.0.0"
    assert diff.changed[0].current_version == "2.1.0"


def test_new_cve_detected() -> None:
    prev = _report(_result("numpy", cve_ids=[]))
    curr = _report(_result("numpy", cve_ids=["CVE-2024-1"]))
    diff = compute(prev, curr)
    assert len(diff.changed) == 1
    assert "CVE-2024-1" in diff.changed[0].new_cves


def test_resolved_cve_detected() -> None:
    prev = _report(_result("numpy", cve_ids=["CVE-2023-5"]))
    curr = _report(_result("numpy", cve_ids=[]))
    diff = compute(prev, curr)
    assert "CVE-2023-5" in diff.changed[0].resolved_cves


def test_status_change_detected() -> None:
    prev = _report(_result("scipy", status=PackageStatus.OK))
    curr = _report(_result("scipy", status=PackageStatus.OUTDATED))
    diff = compute(prev, curr)
    assert len(diff.changed) == 1


def test_is_empty_true_for_two_empty_reports() -> None:
    diff = compute(_report(), _report())
    assert diff.is_empty
