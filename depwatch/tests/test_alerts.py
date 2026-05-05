"""Tests for depwatch.alerts."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from depwatch.alerts import _format_report, dispatch, log_alert, send_email_alert
from depwatch.checker import CheckResult
from depwatch.config import AlertConfig


def _alert_config(**kwargs) -> AlertConfig:
    defaults = dict(
        channel="log",
        email_to="ops@example.com",
        email_from="depwatch@example.com",
        email_subject="depwatch alert",
        smtp_host="localhost",
        smtp_port=25,
        smtp_tls=False,
        smtp_user=None,
        smtp_password=None,
    )
    defaults.update(kwargs)
    return AlertConfig(**defaults)


def _outdated() -> CheckResult:
    return CheckResult(package="requests", current_version="2.28.0",
                       latest_version="2.31.0", cves=[])


def _vulnerable() -> CheckResult:
    return CheckResult(package="pillow", current_version="9.0.0",
                       latest_version="9.0.0", cves=["CVE-2023-1234"])


def _ok() -> CheckResult:
    return CheckResult(package="click", current_version="8.1.0",
                       latest_version="8.1.0", cves=[])


class TestFormatReport:
    def test_outdated_package_appears(self):
        report = _format_report([_outdated()])
        assert "[OUTDATED] requests" in report
        assert "2.28.0 -> 2.31.0" in report

    def test_cve_appears(self):
        report = _format_report([_vulnerable()])
        assert "[CVE]" in report
        assert "CVE-2023-1234" in report

    def test_all_ok_message(self):
        report = _format_report([_ok()])
        assert "up-to-date" in report


class TestLogAlert:
    def test_returns_true(self):
        assert log_alert([_outdated()]) is True


class TestSendEmailAlert:
    def test_returns_false_when_not_configured(self):
        cfg = _alert_config(smtp_host=None)
        assert send_email_alert([_outdated()], cfg) is False

    def test_sends_via_smtp(self):
        cfg = _alert_config(channel="email")
        with patch("depwatch.alerts.smtplib.SMTP") as mock_smtp_cls:
            ctx = MagicMock()
            mock_smtp_cls.return_value.__enter__ = lambda s: ctx
            mock_smtp_cls.return_value.__exit__ = MagicMock(return_value=False)
            result = send_email_alert([_outdated()], cfg)
        assert result is True

    def test_returns_false_on_smtp_error(self):
        cfg = _alert_config(channel="email")
        with patch("depwatch.alerts.smtplib.SMTP", side_effect=OSError("refused")):
            result = send_email_alert([_outdated()], cfg)
        assert result is False


class TestDispatch:
    def test_no_action_when_all_ok(self, caplog):
        dispatch([_ok()], _alert_config())
        assert not any("OUTDATED" in r.message for r in caplog.records)

    def test_log_channel_triggers_log_alert(self):
        with patch("depwatch.alerts.log_alert", return_value=True) as mock_log:
            dispatch([_outdated()], _alert_config(channel="log"))
        mock_log.assert_called_once()

    def test_email_channel_triggers_email_alert(self):
        with patch("depwatch.alerts.send_email_alert", return_value=True) as mock_email:
            dispatch([_outdated()], _alert_config(channel="email"))
        mock_email.assert_called_once()
