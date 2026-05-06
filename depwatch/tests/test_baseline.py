"""Tests for depwatch.baseline."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from depwatch import baseline as bl
from depwatch.checker import CheckResult, PackageStatus
from depwatch.cve import CVEResult, Vulnerability
from depwatch.scanner import ScanReport


def _vuln(cve_id: str) -> Vulnerability:
    v = MagicMock(spec=Vulnerability)
    v.cve_id = cve_id
    return v


def _result(name: str, installed: str = "1.0.0", latest: str = "1.0.0",
            cve_ids: list[str] | None = None) -> CheckResult:
    cve_result = MagicMock(spec=CVEResult)
    cve_result.vulnerabilities = [_vuln(c) for c in (cve_ids or [])]
    return CheckResult(
        package_name=name,
        installed_version=installed,
        latest_version=latest,
        status=PackageStatus.OK,
        cve_result=cve_result,
    )


@pytest.fixture()
def tmp_path_baseline(tmp_path: Path) -> Path:
    return tmp_path / "baseline.json"


def test_save_creates_file(tmp_path_baseline: Path) -> None:
    report = ScanReport(results=[_result("requests", cve_ids=["CVE-2023-1"])])
    bl.save(report, tmp_path_baseline)
    assert tmp_path_baseline.exists()


def test_save_contains_package_entry(tmp_path_baseline: Path) -> None:
    report = ScanReport(results=[_result("flask", installed="2.0.0", cve_ids=["CVE-2024-1"])])
    bl.save(report, tmp_path_baseline)
    data = json.loads(tmp_path_baseline.read_text())
    assert "flask" in data["packages"]
    assert data["packages"]["flask"]["cve_ids"] == ["CVE-2024-1"]


def test_save_records_timestamp(tmp_path_baseline: Path) -> None:
    report = ScanReport(results=[])
    bl.save(report, tmp_path_baseline)
    data = json.loads(tmp_path_baseline.read_text())
    assert data["created_at"] is not None


def test_load_returns_empty_when_missing(tmp_path: Path) -> None:
    result = bl.load(tmp_path / "nonexistent.json")
    assert result["packages"] == {}
    assert result["created_at"] is None


def test_load_round_trips(tmp_path_baseline: Path) -> None:
    report = ScanReport(results=[_result("numpy", cve_ids=["CVE-2022-5"])])
    bl.save(report, tmp_path_baseline)
    loaded = bl.load(tmp_path_baseline)
    assert loaded["packages"]["numpy"]["cve_ids"] == ["CVE-2022-5"]


def test_is_new_issue_unknown_package_with_cve() -> None:
    baseline: dict = {"packages": {}}
    assert bl.is_new_issue("newpkg", "1.0", ["CVE-2024-99"], baseline) is True


def test_is_new_issue_known_cve_not_new() -> None:
    baseline: dict = {"packages": {"requests": {"cve_ids": ["CVE-2023-1"]}}}
    assert bl.is_new_issue("requests", "1.0", ["CVE-2023-1"], baseline) is False


def test_is_new_issue_additional_cve_is_new() -> None:
    baseline: dict = {"packages": {"requests": {"cve_ids": ["CVE-2023-1"]}}}
    assert bl.is_new_issue("requests", "1.0", ["CVE-2023-1", "CVE-2024-2"], baseline) is True


def test_is_new_issue_unknown_package_no_cve() -> None:
    baseline: dict = {"packages": {}}
    assert bl.is_new_issue("brand_new", "1.0", [], baseline) is False
