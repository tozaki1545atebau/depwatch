"""Tests for depwatch.snooze."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from depwatch.snooze import active_snoozes, is_snoozed, snooze, unsnooze

_NOW = datetime(2024, 6, 1, 12, 0, 0, tzinfo=timezone.utc)
_FUTURE = _NOW + timedelta(hours=24)
_PAST = _NOW - timedelta(hours=1)


@pytest.fixture()
def snooze_file(tmp_path: Path) -> Path:
    return tmp_path / "snooze.json"


def test_snooze_creates_file(snooze_file: Path) -> None:
    snooze("requests", "CVE-2023-0001", _FUTURE, path=snooze_file)
    assert snooze_file.exists()


def test_is_snoozed_returns_true_within_window(snooze_file: Path) -> None:
    snooze("requests", "CVE-2023-0001", _FUTURE, path=snooze_file)
    assert is_snoozed("requests", "CVE-2023-0001", path=snooze_file, now=_NOW)


def test_is_snoozed_returns_false_after_expiry(snooze_file: Path) -> None:
    snooze("requests", "CVE-2023-0001", _PAST, path=snooze_file)
    assert not is_snoozed("requests", "CVE-2023-0001", path=snooze_file, now=_NOW)


def test_is_snoozed_returns_false_when_no_file(snooze_file: Path) -> None:
    assert not is_snoozed("requests", "CVE-2023-0001", path=snooze_file, now=_NOW)


def test_is_snoozed_returns_false_for_unknown_package(snooze_file: Path) -> None:
    snooze("requests", "CVE-2023-0001", _FUTURE, path=snooze_file)
    assert not is_snoozed("urllib3", "CVE-2023-0001", path=snooze_file, now=_NOW)


def test_unsnooze_removes_entry(snooze_file: Path) -> None:
    snooze("requests", "CVE-2023-0001", _FUTURE, path=snooze_file)
    unsnooze("requests", "CVE-2023-0001", path=snooze_file)
    assert not is_snoozed("requests", "CVE-2023-0001", path=snooze_file, now=_NOW)


def test_unsnooze_is_idempotent_when_missing(snooze_file: Path) -> None:
    # Should not raise even if the entry does not exist
    unsnooze("requests", "CVE-2023-0001", path=snooze_file)


def test_multiple_packages_tracked_independently(snooze_file: Path) -> None:
    snooze("requests", "CVE-2023-0001", _FUTURE, path=snooze_file)
    snooze("urllib3", "CVE-2023-9999", _PAST, path=snooze_file)
    assert is_snoozed("requests", "CVE-2023-0001", path=snooze_file, now=_NOW)
    assert not is_snoozed("urllib3", "CVE-2023-9999", path=snooze_file, now=_NOW)


def test_active_snoozes_excludes_expired(snooze_file: Path) -> None:
    snooze("requests", "CVE-2023-0001", _FUTURE, path=snooze_file)
    snooze("urllib3", "CVE-2023-9999", _PAST, path=snooze_file)
    active = active_snoozes(path=snooze_file, now=_NOW)
    assert "requests::CVE-2023-0001" in active
    assert "urllib3::CVE-2023-9999" not in active


def test_active_snoozes_empty_when_no_file(snooze_file: Path) -> None:
    assert active_snoozes(path=snooze_file, now=_NOW) == {}


def test_snooze_overwrite_extends_expiry(snooze_file: Path) -> None:
    snooze("requests", "CVE-2023-0001", _PAST, path=snooze_file)
    snooze("requests", "CVE-2023-0001", _FUTURE, path=snooze_file)
    assert is_snoozed("requests", "CVE-2023-0001", path=snooze_file, now=_NOW)
