"""Tests for depwatch.summary_cache."""

from __future__ import annotations

import json
import time
from pathlib import Path
from unittest.mock import patch

import pytest

import depwatch.summary_cache as sc

_SAMPLE = {"total": 5, "outdated": 2, "vulnerable": 1}


@pytest.fixture()
def cache_dir(tmp_path: Path) -> Path:
    return tmp_path / "cache"


def test_save_creates_file(cache_dir: Path) -> None:
    sc.save(cache_dir, _SAMPLE)
    assert _cache_file(cache_dir).exists()


def test_load_returns_summary_within_ttl(cache_dir: Path) -> None:
    sc.save(cache_dir, _SAMPLE, ttl=60)
    result = sc.load(cache_dir)
    assert result == _SAMPLE


def test_load_returns_none_when_expired(cache_dir: Path) -> None:
    with patch.object(sc, "_utcnow", return_value=1_000.0):
        sc.save(cache_dir, _SAMPLE, ttl=10)
    with patch.object(sc, "_utcnow", return_value=1_020.0):
        result = sc.load(cache_dir)
    assert result is None


def test_load_returns_none_when_no_file(cache_dir: Path) -> None:
    assert sc.load(cache_dir) is None


def test_load_returns_none_on_corrupt_file(cache_dir: Path) -> None:
    cache_dir.mkdir(parents=True)
    _cache_file(cache_dir).write_text("not json")
    assert sc.load(cache_dir) is None


def test_invalidate_removes_file(cache_dir: Path) -> None:
    sc.save(cache_dir, _SAMPLE)
    sc.invalidate(cache_dir)
    assert not _cache_file(cache_dir).exists()


def test_invalidate_is_noop_when_no_file(cache_dir: Path) -> None:
    sc.invalidate(cache_dir)  # should not raise


def test_is_valid_true_within_ttl(cache_dir: Path) -> None:
    sc.save(cache_dir, _SAMPLE, ttl=60)
    assert sc.is_valid(cache_dir) is True


def test_is_valid_false_when_expired(cache_dir: Path) -> None:
    with patch.object(sc, "_utcnow", return_value=1_000.0):
        sc.save(cache_dir, _SAMPLE, ttl=5)
    with patch.object(sc, "_utcnow", return_value=1_100.0):
        assert sc.is_valid(cache_dir) is False


def test_save_overwrites_previous_entry(cache_dir: Path) -> None:
    sc.save(cache_dir, _SAMPLE)
    new_summary = {"total": 10}
    sc.save(cache_dir, new_summary)
    assert sc.load(cache_dir) == new_summary


def test_save_creates_parent_dirs(tmp_path: Path) -> None:
    deep = tmp_path / "a" / "b" / "c"
    sc.save(deep, _SAMPLE)
    assert sc.load(deep) == _SAMPLE


def _cache_file(base_dir: Path) -> Path:
    return base_dir / ".depwatch_summary_cache.json"
