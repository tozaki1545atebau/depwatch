"""Tests for depwatch.webhook."""

from __future__ import annotations

import json
from unittest.mock import MagicMock, patch

import pytest
import requests

from depwatch.checker import CheckResult, PackageStatus
from depwatch.cve import CVEResult, Vulnerability
from depwatch.scanner import ScanReport
from depwatch.webhook import WebhookConfig, _build_payload, send


def _vuln(cve_id: str = "CVE-2024-0001") -> Vulnerability:
    return Vulnerability(cve_id=cve_id, summary="test vuln", severity="HIGH", url="https://osv.dev/x")


def _result(
    package: str = "requests",
    status: PackageStatus = PackageStatus.OUTDATED,
    vulns: list[Vulnerability] | None = None,
) -> CheckResult:
    cve_result = CVEResult(package=package, vulnerabilities=vulns or [])
    return CheckResult(
        package=package,
        current_version="1.0.0",
        latest_version="2.0.0",
        status=status,
        cve_result=cve_result,
    )


@pytest.fixture()
def simple_report() -> ScanReport:
    return ScanReport(
        results=[
            _result("requests", PackageStatus.OUTDATED),
            _result("flask", PackageStatus.VULNERABLE, vulns=[_vuln()]),
            _result("click", PackageStatus.OK),
        ]
    )


class TestBuildPayload:
    def test_contains_summary_key(self, simple_report):
        payload = _build_payload(simple_report)
        assert "summary" in payload

    def test_outdated_list_length(self, simple_report):
        payload = _build_payload(simple_report)
        assert len(payload["outdated"]) == 1
        assert payload["outdated"][0]["package"] == "requests"

    def test_vulnerable_list_length(self, simple_report):
        payload = _build_payload(simple_report)
        assert len(payload["vulnerable"]) == 1
        assert payload["vulnerable"][0]["package"] == "flask"

    def test_cve_ids_present(self, simple_report):
        payload = _build_payload(simple_report)
        assert "CVE-2024-0001" in payload["vulnerable"][0]["cve_ids"]

    def test_payload_is_json_serialisable(self, simple_report):
        payload = _build_payload(simple_report)
        assert json.loads(json.dumps(payload)) == payload


class TestSend:
    def _cfg(self, url: str = "https://example.com/hook", secret: str | None = None) -> WebhookConfig:
        return WebhookConfig(url=url, secret=secret, timeout=5)

    def test_returns_true_on_success(self, simple_report):
        mock_resp = MagicMock(status_code=200)
        mock_resp.raise_for_status.return_value = None
        with patch("depwatch.webhook.requests.post", return_value=mock_resp) as mock_post:
            result = send(simple_report, self._cfg())
        assert result is True
        mock_post.assert_called_once()

    def test_secret_added_to_headers(self, simple_report):
        mock_resp = MagicMock(status_code=200)
        mock_resp.raise_for_status.return_value = None
        with patch("depwatch.webhook.requests.post", return_value=mock_resp) as mock_post:
            send(simple_report, self._cfg(secret="mysecret"))
        _, kwargs = mock_post.call_args
        assert kwargs["headers"]["X-Depwatch-Secret"] == "mysecret"

    def test_returns_false_on_http_error(self, simple_report):
        with patch("depwatch.webhook.requests.post", side_effect=requests.HTTPError("boom")):
            result = send(simple_report, self._cfg())
        assert result is False

    def test_returns_false_on_connection_error(self, simple_report):
        with patch("depwatch.webhook.requests.post", side_effect=requests.ConnectionError()):
            result = send(simple_report, self._cfg())
        assert result is False

    def test_no_secret_header_when_none(self, simple_report):
        mock_resp = MagicMock(status_code=200)
        mock_resp.raise_for_status.return_value = None
        with patch("depwatch.webhook.requests.post", return_value=mock_resp) as mock_post:
            send(simple_report, self._cfg(secret=None))
        _, kwargs = mock_post.call_args
        assert "X-Depwatch-Secret" not in kwargs["headers"]
