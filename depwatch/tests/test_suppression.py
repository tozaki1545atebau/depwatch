"""Tests for depwatch.suppression."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from depwatch.suppression import is_suppressed, load_all, suppress, unsuppress


@pytest.fixture()
def sup_file(tmp_path: Path) -> Path:
    return tmp_path / "suppressions.json"


def test_suppress_creates_file(sup_file: Path) -> None:
    suppress("CVE-2023-0001", "accepted risk", path=sup_file)
    assert sup_file.exists()


def test_is_suppressed_returns_true_after_suppress(sup_file: Path) -> None:
    suppress("CVE-2023-0001", "accepted risk", path=sup_file)
    assert is_suppressed("CVE-2023-0001", path=sup_file) is True


def test_is_suppressed_returns_false_for_unknown(sup_file: Path) -> None:
    assert is_suppressed("CVE-9999-9999", path=sup_file) is False


def test_is_suppressed_returns_false_when_no_file(sup_file: Path) -> None:
    assert is_suppressed("CVE-2023-0001", path=sup_file) is False


def test_suppress_stores_reason(sup_file: Path) -> None:
    suppress("CVE-2023-0002", "false positive", path=sup_file)
    data = load_all(path=sup_file)
    assert data["CVE-2023-0002"]["reason"] == "false positive"


def test_suppress_stores_timestamp(sup_file: Path) -> None:
    suppress("CVE-2023-0003", "wontfix", path=sup_file)
    data = load_all(path=sup_file)
    assert "suppressed_at" in data["CVE-2023-0003"]


def test_expired_suppression_returns_false(sup_file: Path) -> None:
    past = (datetime.now(timezone.utc) - timedelta(days=1)).isoformat()
    suppress("CVE-2023-0004", "temp", expires=past, path=sup_file)
    assert is_suppressed("CVE-2023-0004", path=sup_file) is False


def test_future_expiry_still_suppressed(sup_file: Path) -> None:
    future = (datetime.now(timezone.utc) + timedelta(days=30)).isoformat()
    suppress("CVE-2023-0005", "temp", expires=future, path=sup_file)
    assert is_suppressed("CVE-2023-0005", path=sup_file) is True


def test_unsuppress_removes_entry(sup_file: Path) -> None:
    suppress("CVE-2023-0006", "accepted", path=sup_file)
    result = unsuppress("CVE-2023-0006", path=sup_file)
    assert result is True
    assert is_suppressed("CVE-2023-0006", path=sup_file) is False


def test_unsuppress_returns_false_when_not_present(sup_file: Path) -> None:
    assert unsuppress("CVE-9999-0000", path=sup_file) is False


def test_multiple_suppressions_coexist(sup_file: Path) -> None:
    suppress("CVE-2023-0007", "r1", path=sup_file)
    suppress("CVE-2023-0008", "r2", path=sup_file)
    assert is_suppressed("CVE-2023-0007", path=sup_file) is True
    assert is_suppressed("CVE-2023-0008", path=sup_file) is True


def test_load_all_returns_all_entries(sup_file: Path) -> None:
    suppress("CVE-2023-0009", "r1", path=sup_file)
    suppress("CVE-2023-0010", "r2", path=sup_file)
    data = load_all(path=sup_file)
    assert len(data) == 2
