"""Tests for depwatch.trend."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch

import pytest

from depwatch.checker import CheckResult, PackageStatus
from depwatch.cve import CVEResult, Vulnerability
from depwatch.scanner import ScanReport
from depwatch.trend import TrendPoint, load, record, summarise


FAKE_TS = "2024-06-01T12:00:00+00:00"


def _vuln() -> Vulnerability:
    return Vulnerability(cve_id="CVE-2024-1", summary="test", severity="HIGH", url="http://x")


def _result(name: str, status: PackageStatus, vuln: bool = False) -> CheckResult:
    vulns = [_vuln()] if vuln else []
    return CheckResult(
        package=name,
        installed="1.0.0",
        latest="2.0.0" if status == PackageStatus.OUTDATED else "1.0.0",
        status=status,
        cve=CVEResult(package=name, vulnerabilities=vulns),
    )


@pytest.fixture()
def trend_file(tmp_path: Path) -> Path:
    return tmp_path / "trend.json"


@pytest.fixture()
def simple_report() -> ScanReport:
    return ScanReport(
        results=[
            _result("pkgA", PackageStatus.OUTDATED),
            _result("pkgB", PackageStatus.VULNERABLE, vuln=True),
            _result("pkgC", PackageStatus.OK),
        ]
    )


def test_record_creates_file(trend_file: Path, simple_report: ScanReport) -> None:
    with patch("depwatch.trend._utcnow", return_value=FAKE_TS):
        record(simple_report, path=trend_file)
    assert trend_file.exists()


def test_record_returns_trend_point(trend_file: Path, simple_report: ScanReport) -> None:
    with patch("depwatch.trend._utcnow", return_value=FAKE_TS):
        point = record(simple_report, path=trend_file)
    assert isinstance(point, TrendPoint)
    assert point.outdated_count == 1
    assert point.vulnerable_count == 1
    assert point.total_count == 3
    assert point.timestamp == FAKE_TS


def test_record_appends_entries(trend_file: Path, simple_report: ScanReport) -> None:
    with patch("depwatch.trend._utcnow", return_value=FAKE_TS):
        record(simple_report, path=trend_file)
        record(simple_report, path=trend_file)
    raw = json.loads(trend_file.read_text())
    assert len(raw) == 2


def test_load_returns_newest_first(trend_file: Path, simple_report: ScanReport) -> None:
    ts_values = ["2024-06-01T10:00:00+00:00", "2024-06-01T11:00:00+00:00"]
    for ts in ts_values:
        with patch("depwatch.trend._utcnow", return_value=ts):
            record(simple_report, path=trend_file)
    points = load(path=trend_file)
    assert points[0].timestamp == ts_values[1]
    assert points[1].timestamp == ts_values[0]


def test_load_respects_limit(trend_file: Path, simple_report: ScanReport) -> None:
    with patch("depwatch.trend._utcnow", return_value=FAKE_TS):
        for _ in range(5):
            record(simple_report, path=trend_file)
    points = load(path=trend_file, limit=3)
    assert len(points) == 3


def test_load_returns_empty_when_no_file(tmp_path: Path) -> None:
    points = load(path=tmp_path / "missing.json")
    assert points == []


def test_summarise_empty() -> None:
    result = summarise([])
    assert result == {"count": 0}


def test_summarise_statistics(trend_file: Path, simple_report: ScanReport) -> None:
    with patch("depwatch.trend._utcnow", return_value=FAKE_TS):
        record(simple_report, path=trend_file)
    points = load(path=trend_file)
    stats = summarise(points)
    assert stats["count"] == 1
    assert stats["outdated"]["latest"] == 1
    assert stats["vulnerable"]["latest"] == 1
