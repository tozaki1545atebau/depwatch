"""Tests for depwatch.checker module."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import httpx
import pytest

from depwatch.checker import (
    CheckResult,
    PackageStatus,
    check_packages,
    fetch_latest_version,
)


def _make_response(version: str, status_code: int = 200) -> MagicMock:
    resp = MagicMock(spec=httpx.Response)
    resp.status_code = status_code
    resp.json.return_value = {"info": {"version": version}}
    resp.raise_for_status = MagicMock(
        side_effect=httpx.HTTPStatusError(
            "error", request=MagicMock(), response=resp
        )
        if status_code >= 400
        else MagicMock()
    )
    return resp


class TestFetchLatestVersion:
    def test_returns_version_on_success(self):
        client = MagicMock(spec=httpx.Client)
        client.get.return_value = _make_response("2.0.0")
        result = fetch_latest_version("requests", client)
        assert result == "2.0.0"

    def test_returns_none_on_http_error(self):
        client = MagicMock(spec=httpx.Client)
        client.get.return_value = _make_response("1.0.0", status_code=404)
        result = fetch_latest_version("nonexistent-pkg", client)
        assert result is None

    def test_returns_none_on_request_error(self):
        client = MagicMock(spec=httpx.Client)
        client.get.side_effect = httpx.RequestError("network failure")
        result = fetch_latest_version("requests", client)
        assert result is None


class TestCheckPackages:
    @patch("depwatch.checker.fetch_latest_version")
    def test_detects_outdated_package(self, mock_fetch):
        mock_fetch.return_value = "3.0.0"
        result = check_packages({"requests": "2.28.0"})
        assert len(result.outdated) == 1
        assert result.outdated[0].name == "requests"
        assert result.outdated[0].latest_version == "3.0.0"
        assert result.outdated[0].is_outdated is True

    @patch("depwatch.checker.fetch_latest_version")
    def test_up_to_date_package(self, mock_fetch):
        mock_fetch.return_value = "2.28.0"
        result = check_packages({"requests": "2.28.0"})
        assert len(result.up_to_date) == 1
        assert result.up_to_date[0].is_outdated is False

    @patch("depwatch.checker.fetch_latest_version")
    def test_pypi_failure_goes_to_errors(self, mock_fetch):
        mock_fetch.return_value = None
        result = check_packages({"broken-pkg": "1.0.0"})
        assert len(result.errors) == 1
        assert result.errors[0].error is not None

    @patch("depwatch.checker.fetch_latest_version")
    def test_total_count(self, mock_fetch):
        mock_fetch.side_effect = ["2.0.0", "1.5.0", None]
        result = check_packages({"pkgA": "1.0.0", "pkgB": "1.5.0", "pkgC": "0.1"})
        assert result.total == 3
        assert len(result.outdated) == 1
        assert len(result.up_to_date) == 1
        assert len(result.errors) == 1
