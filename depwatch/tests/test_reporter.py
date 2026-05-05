"""Tests for depwatch.reporter."""
from __future__ import annotations

import json
from unittest.mock import patch

import pytest

from depwatch.checker import CheckResult
from depwatch.cve import Vulnerability
from depwatch.reporter import render, render_json, render_text
from depwatch.scanner import ScanReport

_FIXED_TS = "2024-01-15T12:00:00+00:00"


def _vuln(cve_id: str = "CVE-2024-0001") -> Vulnerability:
    return Vulnerability(cve_id=cve_id, severity="HIGH", description="A flaw.")


def _result(
    pkg: str = "requests",
    current: str = "2.28.0",
    latest: str | None = "2.31.0",
    vulns: list[Vulnerability] | None = None,
) -> CheckResult:
    return CheckResult(
        package=pkg,
        current_version=current,
        latest_version=latest,
        vulnerabilities=vulns or [],
    )


@pytest.fixture()
def _patch_ts():
    with patch("depwatch.reporter._utcnow", return_value=_FIXED_TS):
        yield


class TestRenderText:
    def test_header_contains_timestamp(self, _patch_ts):
        report = ScanReport(results=[])
        text = render_text(report)
        assert _FIXED_TS in text

    def test_all_ok_message(self, _patch_ts):
        report = ScanReport(results=[_result(latest="2.28.0")])
        text = render_text(report)
        assert "up-to-date" in text

    def test_outdated_package_listed(self, _patch_ts):
        report = ScanReport(results=[_result()])
        text = render_text(report)
        assert "requests" in text
        assert "2.31.0" in text

    def test_vulnerable_package_listed(self, _patch_ts):
        report = ScanReport(results=[_result(latest=None, vulns=[_vuln()])])
        text = render_text(report)
        assert "CVE-2024-0001" in text

    def test_counts_in_header(self, _patch_ts):
        results = [_result(), _result(pkg="flask", current="3.0.0", latest="3.0.0")]
        report = ScanReport(results=results)
        text = render_text(report)
        assert "Outdated         : 1" in text


class TestRenderJson:
    def test_valid_json(self, _patch_ts):
        report = ScanReport(results=[_result()])
        data = json.loads(render_json(report))
        assert "packages" in data
        assert "summary" in data

    def test_summary_counts(self, _patch_ts):
        report = ScanReport(results=[_result(), _result(pkg="flask", latest=None, vulns=[_vuln()])])
        data = json.loads(render_json(report))
        assert data["summary"]["total"] == 2
        assert data["summary"]["outdated"] == 1
        assert data["summary"]["vulnerable"] == 1

    def test_vulnerability_fields_present(self, _patch_ts):
        report = ScanReport(results=[_result(latest=None, vulns=[_vuln()])])
        data = json.loads(render_json(report))
        vuln = data["packages"][0]["vulnerabilities"][0]
        assert vuln["cve_id"] == "CVE-2024-0001"
        assert vuln["severity"] == "HIGH"

    def test_generated_at_field(self, _patch_ts):
        report = ScanReport(results=[])
        data = json.loads(render_json(report))
        assert data["generated_at"] == _FIXED_TS


class TestRenderDispatch:
    def test_default_is_text(self, _patch_ts):
        report = ScanReport(results=[])
        assert render(report) == render_text(report)

    def test_json_format(self, _patch_ts):
        report = ScanReport(results=[])
        assert render(report, fmt="json") == render_json(report)
