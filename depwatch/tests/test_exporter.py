"""Tests for depwatch.exporter."""

from __future__ import annotations

import csv
import io
import json
from unittest.mock import patch

import pytest

from depwatch.checker import CheckResult
from depwatch.cve import Vulnerability
from depwatch.exporter import export, export_csv, export_json
from depwatch.scanner import ScanReport

_FIXED_TS = "2024-01-15T12:00:00+00:00"


def _vuln(vuln_id: str = "GHSA-0000", severity: str = "HIGH") -> Vulnerability:
    return Vulnerability(vuln_id=vuln_id, summary="A flaw", severity=severity)


def _result(
    package: str = "requests",
    current: str = "2.28.0",
    latest: str = "2.31.0",
    outdated: bool = True,
    vulns: list[Vulnerability] | None = None,
) -> CheckResult:
    return CheckResult(
        package=package,
        current_version=current,
        latest_version=latest,
        is_outdated=outdated,
        vulnerabilities=vulns or [],
    )


@pytest.fixture()
def simple_report() -> ScanReport:
    return ScanReport(
        results=[
            _result(vulns=[_vuln()]),
            _result(package="flask", current="2.0.0", latest="2.0.0", outdated=False),
        ]
    )


class TestExportJson:
    def test_output_is_valid_json(self, simple_report: ScanReport) -> None:
        out = export_json(simple_report, timestamp=_FIXED_TS)
        data = json.loads(out)
        assert isinstance(data, dict)

    def test_timestamp_is_included(self, simple_report: ScanReport) -> None:
        data = json.loads(export_json(simple_report, timestamp=_FIXED_TS))
        assert data["generated_at"] == _FIXED_TS

    def test_packages_list_length(self, simple_report: ScanReport) -> None:
        data = json.loads(export_json(simple_report, timestamp=_FIXED_TS))
        assert len(data["packages"]) == 2

    def test_vulnerability_fields_present(self, simple_report: ScanReport) -> None:
        data = json.loads(export_json(simple_report, timestamp=_FIXED_TS))
        vuln = data["packages"][0]["vulnerabilities"][0]
        assert vuln["id"] == "GHSA-0000"
        assert vuln["severity"] == "HIGH"

    def test_uses_utcnow_when_no_timestamp(self, simple_report: ScanReport) -> None:
        with patch("depwatch.exporter._utcnow", return_value=_FIXED_TS):
            data = json.loads(export_json(simple_report))
        assert data["generated_at"] == _FIXED_TS


class TestExportCsv:
    def test_output_has_header_row(self, simple_report: ScanReport) -> None:
        out = export_csv(simple_report)
        reader = csv.DictReader(io.StringIO(out))
        assert "package" in (reader.fieldnames or [])

    def test_row_count_matches_results(self, simple_report: ScanReport) -> None:
        out = export_csv(simple_report)
        rows = list(csv.DictReader(io.StringIO(out)))
        assert len(rows) == 2

    def test_vulnerability_ids_joined(self, simple_report: ScanReport) -> None:
        out = export_csv(simple_report)
        rows = list(csv.DictReader(io.StringIO(out)))
        assert rows[0]["vulnerability_ids"] == "GHSA-0000"

    def test_no_vulnerabilities_empty_string(self, simple_report: ScanReport) -> None:
        out = export_csv(simple_report)
        rows = list(csv.DictReader(io.StringIO(out)))
        assert rows[1]["vulnerability_ids"] == ""


class TestExportDispatch:
    def test_json_format(self, simple_report: ScanReport) -> None:
        out = export(simple_report, "json", timestamp=_FIXED_TS)
        assert json.loads(out)["generated_at"] == _FIXED_TS

    def test_csv_format(self, simple_report: ScanReport) -> None:
        out = export(simple_report, "csv")
        assert "package" in out

    def test_unknown_format_raises(self, simple_report: ScanReport) -> None:
        with pytest.raises(ValueError, match="Unsupported export format"):
            export(simple_report, "xml")
