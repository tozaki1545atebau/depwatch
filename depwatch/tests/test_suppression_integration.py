"""Integration tests: suppression interacting with CVEResult / ScanReport."""
from __future__ import annotations

from pathlib import Path

from depwatch.checker import CheckResult, PackageStatus
from depwatch.cve import CVEResult, Vulnerability
from depwatch.scanner import ScanReport
from depwatch.suppression import is_suppressed, suppress


def _vuln(cve_id: str) -> Vulnerability:
    return Vulnerability(
        cve_id=cve_id,
        summary="test vulnerability",
        severity="HIGH",
        url=f"https://osv.dev/{cve_id}",
    )


def _result(pkg: str, *cve_ids: str) -> CheckResult:
    vulns = [_vuln(c) for c in cve_ids]
    cve = CVEResult(package=pkg, version="1.0.0", vulnerabilities=vulns)
    return CheckResult(
        package=pkg,
        installed="1.0.0",
        latest="2.0.0",
        status=PackageStatus.VULNERABLE if vulns else PackageStatus.OK,
        cve_result=cve,
    )


def test_suppressed_cve_not_counted_as_vulnerable(tmp_path: Path) -> None:
    sup_file = tmp_path / "sup.json"
    suppress("CVE-2024-1111", "accepted", path=sup_file)

    result = _result("requests", "CVE-2024-1111")
    report = ScanReport(results=[result])

    active_vulns = [
        v
        for r in report.vulnerable()
        for v in r.cve_result.vulnerabilities
        if not is_suppressed(v.cve_id, path=sup_file)
    ]
    assert active_vulns == []


def test_unsuppressed_cve_still_visible(tmp_path: Path) -> None:
    sup_file = tmp_path / "sup.json"
    suppress("CVE-2024-2222", "accepted", path=sup_file)

    result = _result("flask", "CVE-2024-2222", "CVE-2024-3333")
    report = ScanReport(results=[result])

    active_vulns = [
        v
        for r in report.vulnerable()
        for v in r.cve_result.vulnerabilities
        if not is_suppressed(v.cve_id, path=sup_file)
    ]
    assert len(active_vulns) == 1
    assert active_vulns[0].cve_id == "CVE-2024-3333"


def test_no_suppressions_all_vulns_visible(tmp_path: Path) -> None:
    sup_file = tmp_path / "sup.json"

    result = _result("django", "CVE-2024-4444", "CVE-2024-5555")
    report = ScanReport(results=[result])

    active_vulns = [
        v
        for r in report.vulnerable()
        for v in r.cve_result.vulnerabilities
        if not is_suppressed(v.cve_id, path=sup_file)
    ]
    assert len(active_vulns) == 2
