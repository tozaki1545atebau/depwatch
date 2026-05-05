"""Tests for depwatch.cve module."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest
import requests

from depwatch.cve import CVEResult, Vulnerability, check_cves, fetch_vulnerabilities


PACKAGE = "requests"
VERSION = "2.25.0"


def _make_osv_response(vulns: list) -> MagicMock:
    mock = MagicMock()
    mock.json.return_value = {"vulns": vulns}
    mock.raise_for_status.return_value = None
    return mock


SAMPLE_VULN = {
    "id": "GHSA-xxxx-yyyy-zzzz",
    "summary": "Remote code execution in requests",
    "aliases": ["CVE-2021-12345"],
    "severity": [{"score": "HIGH"}],
}


class TestFetchVulnerabilities:
    @patch("depwatch.cve.requests.post")
    def test_returns_empty_when_no_vulns(self, mock_post):
        mock_post.return_value = _make_osv_response([])
        result = fetch_vulnerabilities(PACKAGE, VERSION)
        assert isinstance(result, CVEResult)
        assert result.package == PACKAGE
        assert result.version == VERSION
        assert result.vulnerabilities == []
        assert not result.is_vulnerable

    @patch("depwatch.cve.requests.post")
    def test_parses_vulnerability_fields(self, mock_post):
        mock_post.return_value = _make_osv_response([SAMPLE_VULN])
        result = fetch_vulnerabilities(PACKAGE, VERSION)
        assert result.is_vulnerable
        vuln = result.vulnerabilities[0]
        assert vuln.vuln_id == "GHSA-xxxx-yyyy-zzzz"
        assert "Remote code execution" in vuln.summary
        assert vuln.severity == "HIGH"
        assert "CVE-2021-12345" in vuln.aliases

    @patch("depwatch.cve.requests.post")
    def test_returns_empty_on_http_error(self, mock_post):
        mock_post.return_value.raise_for_status.side_effect = requests.HTTPError("404")
        result = fetch_vulnerabilities(PACKAGE, VERSION)
        assert not result.is_vulnerable

    @patch("depwatch.cve.requests.post")
    def test_returns_empty_on_request_exception(self, mock_post):
        mock_post.side_effect = requests.ConnectionError("timeout")
        result = fetch_vulnerabilities(PACKAGE, VERSION)
        assert not result.is_vulnerable

    @patch("depwatch.cve.requests.post")
    def test_severity_falls_back_to_database_specific(self, mock_post):
        vuln = {**SAMPLE_VULN, "severity": [], "database_specific": {"severity": "MEDIUM"}}
        mock_post.return_value = _make_osv_response([vuln])
        result = fetch_vulnerabilities(PACKAGE, VERSION)
        assert result.vulnerabilities[0].severity == "MEDIUM"

    @patch("depwatch.cve.requests.post")
    def test_multiple_vulnerabilities_are_all_parsed(self, mock_post):
        """All vulnerabilities returned by OSV should be present in the result."""
        second_vuln = {
            "id": "GHSA-aaaa-bbbb-cccc",
            "summary": "SQL injection in requests",
            "aliases": ["CVE-2022-99999"],
            "severity": [{"score": "CRITICAL"}],
        }
        mock_post.return_value = _make_osv_response([SAMPLE_VULN, second_vuln])
        result = fetch_vulnerabilities(PACKAGE, VERSION)
        assert result.is_vulnerable
        assert len(result.vulnerabilities) == 2
        vuln_ids = {v.vuln_id for v in result.vulnerabilities}
        assert "GHSA-xxxx-yyyy-zzzz" in vuln_ids
        assert "GHSA-aaaa-bbbb-cccc" in vuln_ids


class TestCheckCves:
    @patch("depwatch.cve.fetch_vulnerabilities")
    def test_returns_list_of_results(self, mock_fetch):
        mock_fetch.return_value = CVEResult(package="flask", version="1.0.0")
        results = check_cves({"flask": "1.0.0", "django": "3.2.0"})
        assert len(results) == 2
        assert mock_fetch.call_count == 2

    @patch("depwatch.cve.fetch_vulnerabilities")
    def test_empty_packages(self, mock_fetch):
        results = check_cves({})
        assert results == []
        mock_fetch.assert_not_called()
