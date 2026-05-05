"""Tests for depwatch.scanner module."""

from __future__ import annotations

from unittest.mock import patch, MagicMock

import pytest

from depwatch.checker import CheckResult, PackageStatus
from depwatch.config import DepwatchConfig, AlertConfig
from depwatch.cve import CVEResult, Vulnerability
from depwatch.scanner import ScanReport, run_scan, _installed_versions


def _make_config(packages=None, check_cves=True):
    return DepwatchConfig(
        packages=packages or ["requests", "flask"],
        check_cves=check_cves,
        alert=AlertConfig(),
    )


def _check_result(pkg, status, installed="1.0.0", latest="2.0.0"):
    return CheckResult(
        package=pkg,
        installed_version=installed,
        latest_version=latest,
        status=status,
    )


class TestScanReport:
    def test_outdated_filters_correctly(self):
        results = [
            _check_result("flask", PackageStatus.OUTDATED),
            _check_result("requests", PackageStatus.UP_TO_DATE),
        ]
        report = ScanReport(check_results=results)
        assert len(report.outdated) == 1
        assert report.outdated[0].package == "flask"

    def test_vulnerable_filters_correctly(self):
        ok = CVEResult(package="flask", version="1.0.0")
        bad = CVEResult(
            package="requests",
            version="2.25.0",
            vulnerabilities=[Vulnerability(vuln_id="CVE-X", summary="oops")],
        )
        report = ScanReport(cve_results=[ok, bad])
        assert len(report.vulnerable) == 1
        assert report.vulnerable[0].package == "requests"

    def test_has_issues_true_when_outdated(self):
        report = ScanReport(check_results=[_check_result("x", PackageStatus.OUTDATED)])
        assert report.has_issues

    def test_has_issues_false_when_clean(self):
        report = ScanReport(check_results=[_check_result("x", PackageStatus.UP_TO_DATE)])
        assert not report.has_issues

    def test_summary_contains_counts(self):
        report = ScanReport(
            check_results=[_check_result("x", PackageStatus.OUTDATED)],
        )
        s = report.summary()
        assert "1" in s
        assert "Outdated" in s


class TestInstalledVersions:
    def test_extracts_versions(self):
        results = [
            _check_result("flask", PackageStatus.UP_TO_DATE, installed="2.0.0"),
            _check_result("requests", PackageStatus.OUTDATED, installed="2.25.0"),
        ]
        mapping = _installed_versions(results)
        assert mapping == {"flask": "2.0.0", "requests": "2.25.0"}

    def test_skips_none_installed(self):
        result = CheckResult(
            package="broken",
            installed_version=None,
            latest_version=None,
            status=PackageStatus.UNKNOWN,
        )
        assert _installed_versions([result]) == {}


class TestRunScan:
    @patch("depwatch.scanner.check_cves")
    @patch("depwatch.scanner.check_packages")
    def test_full_scan_calls_both(self, mock_check, mock_cve):
        mock_check.return_value = [_check_result("flask", PackageStatus.UP_TO_DATE)]
        mock_cve.return_value = [CVEResult(package="flask", version="1.0.0")]
        report = run_scan(_make_config(check_cves=True))
        mock_check.assert_called_once()
        mock_cve.assert_called_once()
        assert isinstance(report, ScanReport)

    @patch("depwatch.scanner.check_cves")
    @patch("depwatch.scanner.check_packages")
    def test_cve_skipped_when_disabled(self, mock_check, mock_cve):
        mock_check.return_value = []
        report = run_scan(_make_config(check_cves=False))
        mock_cve.assert_not_called()
        assert report.cve_results == []
