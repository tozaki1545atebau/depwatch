"""Configuration loading for depwatch."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

try:
    import tomllib
except ImportError:  # Python < 3.11
    import tomli as tomllib  # type: ignore[no-redef]


@dataclass
class AlertConfig:
    email_to: Optional[str] = None
    email_from: Optional[str] = None
    smtp_host: str = "localhost"
    smtp_port: int = 25
    log_alerts: bool = True


@dataclass
class WebhookAlertConfig:
    url: Optional[str] = None
    secret: Optional[str] = None
    timeout: int = 10
    enabled: bool = False


@dataclass
class DepwatchConfig:
    requirements_file: str = "requirements.txt"
    interval_seconds: int = 3600
    alert: AlertConfig = field(default_factory=AlertConfig)
    webhook: WebhookAlertConfig = field(default_factory=WebhookAlertConfig)


def _parse_alert(raw: dict) -> AlertConfig:
    return AlertConfig(
        email_to=raw.get("email_to"),
        email_from=raw.get("email_from"),
        smtp_host=raw.get("smtp_host", "localhost"),
        smtp_port=int(raw.get("smtp_port", 25)),
        log_alerts=bool(raw.get("log_alerts", True)),
    )


def _parse_webhook(raw: dict) -> WebhookAlertConfig:
    return WebhookAlertConfig(
        url=raw.get("url"),
        secret=raw.get("secret"),
        timeout=int(raw.get("timeout", 10)),
        enabled=bool(raw.get("enabled", False)),
    )


def from_file(path: str | Path) -> DepwatchConfig:
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(f"Config file not found: {path}")
    with p.open("rb") as fh:
        raw = tomllib.load(fh)
    return DepwatchConfig(
        requirements_file=raw.get("requirements_file", "requirements.txt"),
        interval_seconds=int(raw.get("interval_seconds", 3600)),
        alert=_parse_alert(raw.get("alert", {})),
        webhook=_parse_webhook(raw.get("webhook", {})),
    )


def from_env() -> DepwatchConfig:
    alert = AlertConfig(
        email_to=os.environ.get("DEPWATCH_EMAIL_TO"),
        email_from=os.environ.get("DEPWATCH_EMAIL_FROM"),
        smtp_host=os.environ.get("DEPWATCH_SMTP_HOST", "localhost"),
        smtp_port=int(os.environ.get("DEPWATCH_SMTP_PORT", "25")),
        log_alerts=os.environ.get("DEPWATCH_LOG_ALERTS", "true").lower() != "false",
    )
    webhook = WebhookAlertConfig(
        url=os.environ.get("DEPWATCH_WEBHOOK_URL"),
        secret=os.environ.get("DEPWATCH_WEBHOOK_SECRET"),
        timeout=int(os.environ.get("DEPWATCH_WEBHOOK_TIMEOUT", "10")),
        enabled=os.environ.get("DEPWATCH_WEBHOOK_ENABLED", "false").lower() == "true",
    )
    return DepwatchConfig(
        requirements_file=os.environ.get("DEPWATCH_REQUIREMENTS", "requirements.txt"),
        interval_seconds=int(os.environ.get("DEPWATCH_INTERVAL", "3600")),
        alert=alert,
        webhook=webhook,
    )
