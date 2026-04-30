"""Configuration loader for depwatch."""

import os
from dataclasses import dataclass, field
from typing import List, Optional

import tomllib


@dataclass
class AlertConfig:
    email: Optional[str] = None
    slack_webhook: Optional[str] = None
    min_severity: str = "medium"  # low, medium, high, critical


@dataclass
class DepwatchConfig:
    requirements_file: str = "requirements.txt"
    check_interval_seconds: int = 3600
    ignored_packages: List[str] = field(default_factory=list)
    alert: AlertConfig = field(default_factory=AlertConfig)

    @classmethod
    def from_file(cls, path: str) -> "DepwatchConfig":
        """Load configuration from a TOML file."""
        if not os.path.exists(path):
            raise FileNotFoundError(f"Config file not found: {path}")

        with open(path, "rb") as f:
            raw = tomllib.load(f)

        alert_raw = raw.get("alert", {})
        alert = AlertConfig(
            email=alert_raw.get("email"),
            slack_webhook=alert_raw.get("slack_webhook"),
            min_severity=alert_raw.get("min_severity", "medium"),
        )

        return cls(
            requirements_file=raw.get("requirements_file", "requirements.txt"),
            check_interval_seconds=raw.get("check_interval_seconds", 3600),
            ignored_packages=raw.get("ignored_packages", []),
            alert=alert,
        )

    @classmethod
    def from_env(cls) -> "DepwatchConfig":
        """Load configuration from environment variables (overrides defaults)."""
        config = cls()
        if val := os.getenv("DEPWATCH_REQUIREMENTS_FILE"):
            config.requirements_file = val
        if val := os.getenv("DEPWATCH_CHECK_INTERVAL"):
            config.check_interval_seconds = int(val)
        if val := os.getenv("DEPWATCH_IGNORED_PACKAGES"):
            config.ignored_packages = [p.strip() for p in val.split(",")]
        if val := os.getenv("DEPWATCH_ALERT_EMAIL"):
            config.alert.email = val
        if val := os.getenv("DEPWATCH_ALERT_SLACK_WEBHOOK"):
            config.alert.slack_webhook = val
        if val := os.getenv("DEPWATCH_MIN_SEVERITY"):
            config.alert.min_severity = val
        return config
