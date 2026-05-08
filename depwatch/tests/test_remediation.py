"""Tests for depwatch.remediation."""
from __future__ import annotations

import pytest

from depwatch.checker import CheckResult
from depwatch.cve import CVEResult, Vulnerability
from depwatch.scanner import ScanReport
from depwatch.remediation import build_remediation, _upgrade_command, _notes


def _vuln(cve_id: str, severity: str = "HIGH") -> Vulnerability:
    return Vulnerability(cve_id=cve_id, summary="desc", severity=severity, aliases=[])


def _result(
    package: str = "requests",
    current: str = "2.28.0",
    latest: str = "2.31.0",
    vulns=None,
) -> CheckResult:
    cve_result = CVEResult(package=package, vulnerabilities=vulns or [])
    return CheckResult(
        package=package,
        current_version=current,
        latest_version=latest,
        cve_result=cve_result,
    )


def _report(*results: CheckResult) -> ScanReport:
    return ScanReport(results=list(results))


# --- _upgrade_command ---

def test_upgrade_command_with_latest():
    cmd = _upgrade_command("requests", "2.31.0")
    assert cmd == "pip install --upgrade requests==2.31.0"


def test_upgrade_command_without_latest():
    cmd = _upgrade_command("requests", None)
    assert cmd == "pip install --upgrade requests"


# --- build_remediation ---

def test_ok_package_excluded():
    r = _result(current="2.31.0", latest="2.31.0", vulns=[])
    items = build_remediation(_report(r))
    assert items == []


def test_outdated_package_included():
    r = _result(current="2.28.0", latest="2.31.0", vulns=[])
    items = build_remediation(_report(r))
    assert len(items) == 1
    assert items[0].package == "requests"
    assert items[0].latest_version == "2.31.0"


def test_vulnerable_package_included_even_if_up_to_date():
    r = _result(current="2.31.0", latest="2.31.0", vulns=[_vuln("CVE-2024-0001")])
    items = build_remediation(_report(r))
    assert len(items) == 1
    assert "CVE-2024-0001" in items[0].cve_ids


def test_cve_ids_populated():
    vulns = [_vuln("CVE-2024-0001"), _vuln("CVE-2024-0002")]
    r = _result(vulns=vulns)
    items = build_remediation(_report(r))
    assert set(items[0].cve_ids) == {"CVE-2024-0001", "CVE-2024-0002"}


def test_upgrade_command_in_result():
    r = _result(current="2.28.0", latest="2.31.0")
    items = build_remediation(_report(r))
    assert items[0].upgrade_command == "pip install --upgrade requests==2.31.0"


def test_notes_critical_severity():
    r = _result(vulns=[_vuln("CVE-2024-0001", severity="CRITICAL")])
    note = _notes(r)
    assert "CRITICAL" in note


def test_notes_high_severity():
    r = _result(vulns=[_vuln("CVE-2024-0001", severity="HIGH")])
    note = _notes(r)
    assert "HIGH" in note


def test_as_dict_keys():
    r = _result()
    items = build_remediation(_report(r))
    d = items[0].as_dict()
    assert set(d.keys()) == {
        "package", "current_version", "latest_version",
        "cve_ids", "upgrade_command", "notes",
    }


def test_multiple_packages():
    r1 = _result(package="requests", current="2.28.0", latest="2.31.0")
    r2 = _result(package="flask", current="2.0.0", latest="2.0.0", vulns=[])
    r3 = _result(package="django", current="3.2.0", latest="4.2.0")
    items = build_remediation(_report(r1, r2, r3))
    packages = [i.package for i in items]
    assert "requests" in packages
    assert "django" in packages
    assert "flask" not in packages
