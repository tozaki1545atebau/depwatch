"""Integration tests: snooze interacts correctly with scanner results."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from depwatch.cve import CVEResult, Vulnerability
from depwatch.checker import CheckResult, PackageStatus
from depwatch.scanner import ScanReport
from depwatch.snooze import is_snoozed, snooze

_NOW = datetime(2024, 6, 1, 12, 0, 0, tzinfo=timezone.utc)
_FUTURE = _NOW + timedelta(hours=48)


def _vuln(cve_id: str) -> Vulnerability:
    return Vulnerability(
        cve_id=cve_id,
        summary="Test vulnerability",
        severity="HIGH",
        url=f"https://osv.dev/{cve_id}",
    )


def _result(package: str, vulns: list[Vulnerability]) -> CheckResult:
    return CheckResult(
        package=package,
        installed="1.0.0",
        latest="2.0.0",
        status=PackageStatus.OUTDATED,
        cve_result=CVEResult(package=package, version="1.0.0", vulnerabilities=vulns),
    )


@pytest.fixture()
def snooze_file(tmp_path: Path) -> Path:
    return tmp_path / "snooze.json"


def test_snoozed_cve_filtered_from_report(snooze_file: Path) -> None:
    vuln = _vuln("CVE-2024-1111")
    result = _result("requests", [vuln])
    report = ScanReport(results=[result])

    snooze("requests", "CVE-2024-1111", _FUTURE, path=snooze_file)

    # Filter vulnerable packages whose CVEs are all snoozed
    def all_snoozed(r: CheckResult) -> bool:
        if r.cve_result is None:
            return False
        return all(
            is_snoozed(r.package, v.cve_id, path=snooze_file, now=_NOW)
            for v in r.cve_result.vulnerabilities
        )

    unsnoozed_vulnerable = [r for r in report.vulnerable if not all_snoozed(r)]
    assert unsnoozed_vulnerable == []


def test_unsnoozed_cve_still_visible(snooze_file: Path) -> None:
    vuln = _vuln("CVE-2024-2222")
    result = _result("urllib3", [vuln])
    report = ScanReport(results=[result])

    # No snooze applied
    def all_snoozed(r: CheckResult) -> bool:
        if r.cve_result is None:
            return False
        return all(
            is_snoozed(r.package, v.cve_id, path=snooze_file, now=_NOW)
            for v in r.cve_result.vulnerabilities
        )

    unsnoozed_vulnerable = [r for r in report.vulnerable if not all_snoozed(r)]
    assert len(unsnoozed_vulnerable) == 1
    assert unsnoozed_vulnerable[0].package == "urllib3"


def test_partial_snooze_keeps_package_visible(snooze_file: Path) -> None:
    v1 = _vuln("CVE-2024-3333")
    v2 = _vuln("CVE-2024-4444")
    result = _result("flask", [v1, v2])
    report = ScanReport(results=[result])

    # Only snooze one of the two CVEs
    snooze("flask", "CVE-2024-3333", _FUTURE, path=snooze_file)

    def all_snoozed(r: CheckResult) -> bool:
        if r.cve_result is None:
            return False
        return all(
            is_snoozed(r.package, v.cve_id, path=snooze_file, now=_NOW)
            for v in r.cve_result.vulnerabilities
        )

    unsnoozed_vulnerable = [r for r in report.vulnerable if not all_snoozed(r)]
    assert len(unsnoozed_vulnerable) == 1
    assert unsnoozed_vulnerable[0].package == "flask"
