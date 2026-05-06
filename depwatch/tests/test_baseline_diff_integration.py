"""Integration tests combining baseline suppression with diff detection."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock

from depwatch import baseline as bl
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
    cve_ids: list[str] | None = None,
) -> CheckResult:
    cve_result = MagicMock(spec=CVEResult)
    cve_result.vulnerabilities = [_vuln(c) for c in (cve_ids or [])]
    return CheckResult(
        package_name=name,
        installed_version=installed,
        latest_version=installed,
        status=PackageStatus.OK,
        cve_result=cve_result,
    )


def test_known_cves_not_flagged_as_new_after_baseline(tmp_path: Path) -> None:
    baseline_path = tmp_path / "baseline.json"
    initial = ScanReport(results=[_result("requests", cve_ids=["CVE-2023-1"])])
    bl.save(initial, baseline_path)

    loaded = bl.load(baseline_path)
    assert bl.is_new_issue("requests", "1.0.0", ["CVE-2023-1"], loaded) is False


def test_new_cve_after_baseline_flagged(tmp_path: Path) -> None:
    baseline_path = tmp_path / "baseline.json"
    initial = ScanReport(results=[_result("requests", cve_ids=["CVE-2023-1"])])
    bl.save(initial, baseline_path)

    loaded = bl.load(baseline_path)
    assert bl.is_new_issue("requests", "1.0.0", ["CVE-2023-1", "CVE-2024-9"], loaded) is True


def test_diff_and_baseline_agree_on_new_cve(tmp_path: Path) -> None:
    baseline_path = tmp_path / "baseline.json"
    prev_report = ScanReport(results=[_result("flask", cve_ids=["CVE-2022-1"])])
    bl.save(prev_report, baseline_path)

    curr_report = ScanReport(results=[_result("flask", cve_ids=["CVE-2022-1", "CVE-2024-5"])])
    diff = compute(prev_report, curr_report)
    loaded = bl.load(baseline_path)

    new_cves_from_diff = diff.changed[0].new_cves if diff.changed else []
    is_new = bl.is_new_issue("flask", "1.0.0", ["CVE-2022-1", "CVE-2024-5"], loaded)

    assert "CVE-2024-5" in new_cves_from_diff
    assert is_new is True


def test_saving_updated_report_clears_resolved_cves(tmp_path: Path) -> None:
    baseline_path = tmp_path / "baseline.json"
    old = ScanReport(results=[_result("numpy", cve_ids=["CVE-2021-1"])])
    bl.save(old, baseline_path)

    fixed = ScanReport(results=[_result("numpy", cve_ids=[])])
    bl.save(fixed, baseline_path)

    loaded = bl.load(baseline_path)
    assert loaded["packages"]["numpy"]["cve_ids"] == []
