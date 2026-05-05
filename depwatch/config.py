"""Configuration loading for depwatch."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional

try:
    import tomllib
except ImportError:  # Python < 3.11
    import tomli as tomllib  # type: ignore


@dataclass
class AlertConfig:
    email_enabled: bool = False
    email_to: Optional[str] = None
    email_from: Optional[str] = None
    smtp_host: str = "localhost"
    smtp_port: int = 587
    log_enabled: bool = True


@dataclass
class DepwatchConfig:
    packages: List[str] = field(default_factory=list)
    check_interval_seconds: int = 3600
    check_cves: bool = True
    alert: AlertConfig = field(default_factory=AlertConfig)


def _parse_alert(raw: dict) -> AlertConfig:
    alert_raw = raw.get("alert", {})
    return AlertConfig(
        email_enabled=alert_raw.get("email_enabled", False),
        email_to=alert_raw.get("email_to"),
        email_from=alert_raw.get("email_from"),
        smtp_host=alert_raw.get("smtp_host", "localhost"),
        smtp_port=int(alert_raw.get("smtp_port", 587)),
        log_enabled=alert_raw.get("log_enabled", True),
    )


def from_file(path: str | Path = "depwatch.toml") -> DepwatchConfig:
    """Load configuration from a TOML file."""
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(f"Config file not found: {p}")
    with p.open("rb") as fh:
        raw = tomllib.load(fh)
    return DepwatchConfig(
        packages=raw.get("packages", []),
        check_interval_seconds=int(raw.get("check_interval_seconds", 3600)),
        check_cves=bool(raw.get("check_cves", True)),
        alert=_parse_alert(raw),
    )


def from_env() -> DepwatchConfig:
    """Load configuration from environment variables."""
    packages_raw = os.environ.get("DEPWATCH_PACKAGES", "")
    packages = [p.strip() for p in packages_raw.split(",") if p.strip()]
    return DepwatchConfig(
        packages=packages,
        check_interval_seconds=int(os.environ.get("DEPWATCH_INTERVAL", 3600)),
        check_cves=os.environ.get("DEPWATCH_CHECK_CVES", "true").lower() == "true",
        alert=AlertConfig(
            email_enabled=os.environ.get("DEPWATCH_EMAIL_ENABLED", "false").lower() == "true",
            email_to=os.environ.get("DEPWATCH_EMAIL_TO"),
            email_from=os.environ.get("DEPWATCH_EMAIL_FROM"),
            smtp_host=os.environ.get("DEPWATCH_SMTP_HOST", "localhost"),
            smtp_port=int(os.environ.get("DEPWATCH_SMTP_PORT", 587)),
            log_enabled=os.environ.get("DEPWATCH_LOG_ENABLED", "true").lower() == "true",
        ),
    )
