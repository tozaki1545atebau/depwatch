"""Tests for depwatch configuration loading."""

import os
import textwrap
import tempfile
import pytest

from depwatch.config import AlertConfig, DepwatchConfig


@pytest.fixture
def toml_config_file():
    content = textwrap.dedent("""
        requirements_file = "reqs.txt"
        check_interval_seconds = 1800
        ignored_packages = ["boto3", "botocore"]

        [alert]
        email = "ops@example.com"
        slack_webhook = "https://hooks.slack.com/xxx"
        min_severity = "high"
    """)
    with tempfile.NamedTemporaryFile(suffix=".toml", mode="w", delete=False) as f:
        f.write(content)
        tmp_path = f.name
    yield tmp_path
    os.unlink(tmp_path)


def test_load_from_file(toml_config_file):
    config = DepwatchConfig.from_file(toml_config_file)
    assert config.requirements_file == "reqs.txt"
    assert config.check_interval_seconds == 1800
    assert config.ignored_packages == ["boto3", "botocore"]
    assert config.alert.email == "ops@example.com"
    assert config.alert.slack_webhook == "https://hooks.slack.com/xxx"
    assert config.alert.min_severity == "high"


def test_file_not_found_raises():
    with pytest.raises(FileNotFoundError):
        DepwatchConfig.from_file("/nonexistent/path/depwatch.toml")


def test_defaults_when_keys_missing():
    content = b"check_interval_seconds = 600\n"
    with tempfile.NamedTemporaryFile(suffix=".toml", delete=False) as f:
        f.write(content)
        tmp_path = f.name
    try:
        config = DepwatchConfig.from_file(tmp_path)
        assert config.requirements_file == "requirements.txt"
        assert config.ignored_packages == []
        assert config.alert.email is None
        assert config.alert.min_severity == "medium"
    finally:
        os.unlink(tmp_path)


def test_load_from_env(monkeypatch):
    monkeypatch.setenv("DEPWATCH_REQUIREMENTS_FILE", "custom_reqs.txt")
    monkeypatch.setenv("DEPWATCH_CHECK_INTERVAL", "900")
    monkeypatch.setenv("DEPWATCH_IGNORED_PACKAGES", "requests, urllib3")
    monkeypatch.setenv("DEPWATCH_ALERT_EMAIL", "dev@example.com")
    monkeypatch.setenv("DEPWATCH_MIN_SEVERITY", "low")

    config = DepwatchConfig.from_env()
    assert config.requirements_file == "custom_reqs.txt"
    assert config.check_interval_seconds == 900
    assert config.ignored_packages == ["requests", "urllib3"]
    assert config.alert.email == "dev@example.com"
    assert config.alert.min_severity == "low"


def test_env_partial_override(monkeypatch):
    monkeypatch.setenv("DEPWATCH_CHECK_INTERVAL", "300")
    config = DepwatchConfig.from_env()
    assert config.check_interval_seconds == 300
    assert config.requirements_file == "requirements.txt"  # default preserved


def test_invalid_min_severity_raises(toml_config_file):
    """Ensure that an unrecognised severity level is rejected at load time."""
    content = textwrap.dedent("""
        [alert]
        min_severity = "critical"
    """)
    with tempfile.NamedTemporaryFile(suffix=".toml", mode="w", delete=False) as f:
        f.write(content)
        tmp_path = f.name
    try:
        with pytest.raises(ValueError, match="min_severity"):
            DepwatchConfig.from_file(tmp_path)
    finally:
        os.unlink(tmp_path)
