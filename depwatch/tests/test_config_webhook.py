"""Tests for webhook-related config parsing."""

from __future__ import annotations

import textwrap
from pathlib import Path

import pytest

from depwatch.config import WebhookAlertConfig, from_env, from_file


@pytest.fixture()
def toml_with_webhook(tmp_path: Path) -> Path:
    content = textwrap.dedent("""
        requirements_file = "requirements.txt"
        interval_seconds = 600

        [alert]
        log_alerts = true

        [webhook]
        url = "https://hooks.example.com/depwatch"
        secret = "topsecret"
        timeout = 15
        enabled = true
    """)
    p = tmp_path / "depwatch.toml"
    p.write_text(content)
    return p


@pytest.fixture()
def toml_without_webhook(tmp_path: Path) -> Path:
    content = textwrap.dedent("""
        requirements_file = "requirements.txt"
    """)
    p = tmp_path / "depwatch.toml"
    p.write_text(content)
    return p


class TestWebhookFromFile:
    def test_url_parsed(self, toml_with_webhook):
        cfg = from_file(toml_with_webhook)
        assert cfg.webhook.url == "https://hooks.example.com/depwatch"

    def test_secret_parsed(self, toml_with_webhook):
        cfg = from_file(toml_with_webhook)
        assert cfg.webhook.secret == "topsecret"

    def test_timeout_parsed(self, toml_with_webhook):
        cfg = from_file(toml_with_webhook)
        assert cfg.webhook.timeout == 15

    def test_enabled_parsed(self, toml_with_webhook):
        cfg = from_file(toml_with_webhook)
        assert cfg.webhook.enabled is True

    def test_defaults_when_section_absent(self, toml_without_webhook):
        cfg = from_file(toml_without_webhook)
        assert cfg.webhook.url is None
        assert cfg.webhook.enabled is False
        assert cfg.webhook.timeout == 10


class TestWebhookFromEnv:
    def test_url_from_env(self, monkeypatch):
        monkeypatch.setenv("DEPWATCH_WEBHOOK_URL", "https://env.example.com/hook")
        cfg = from_env()
        assert cfg.webhook.url == "https://env.example.com/hook"

    def test_enabled_from_env(self, monkeypatch):
        monkeypatch.setenv("DEPWATCH_WEBHOOK_ENABLED", "true")
        cfg = from_env()
        assert cfg.webhook.enabled is True

    def test_secret_from_env(self, monkeypatch):
        monkeypatch.setenv("DEPWATCH_WEBHOOK_SECRET", "envsecret")
        cfg = from_env()
        assert cfg.webhook.secret == "envsecret"

    def test_timeout_from_env(self, monkeypatch):
        monkeypatch.setenv("DEPWATCH_WEBHOOK_TIMEOUT", "30")
        cfg = from_env()
        assert cfg.webhook.timeout == 30

    def test_defaults_when_env_absent(self, monkeypatch):
        for key in ("DEPWATCH_WEBHOOK_URL", "DEPWATCH_WEBHOOK_SECRET",
                    "DEPWATCH_WEBHOOK_ENABLED", "DEPWATCH_WEBHOOK_TIMEOUT"):
            monkeypatch.delenv(key, raising=False)
        cfg = from_env()
        assert cfg.webhook.url is None
        assert cfg.webhook.enabled is False
        assert cfg.webhook.timeout == 10
