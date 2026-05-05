"""Tests for depwatch.history module."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from depwatch import history


@pytest.fixture()
def hist_file(tmp_path: Path) -> Path:
    return tmp_path / "history.json"


# ---------------------------------------------------------------------------
# record / load
# ---------------------------------------------------------------------------

def test_record_creates_file(hist_file):
    history.record({"outdated": 1, "vulnerable": 0}, path=hist_file)
    assert hist_file.exists()


def test_record_adds_entry(hist_file):
    history.record({"outdated": 2, "vulnerable": 1}, path=hist_file)
    entries = history.load(path=hist_file)
    assert len(entries) == 1
    assert entries[0]["outdated"] == 2
    assert entries[0]["vulnerable"] == 1


def test_record_includes_timestamp(hist_file):
    history.record({"outdated": 0, "vulnerable": 0}, path=hist_file)
    entries = history.load(path=hist_file)
    assert "recorded_at" in entries[0]


def test_load_returns_newest_first(hist_file):
    history.record({"seq": 1}, path=hist_file)
    history.record({"seq": 2}, path=hist_file)
    history.record({"seq": 3}, path=hist_file)
    entries = history.load(path=hist_file)
    assert entries[0]["seq"] == 3
    assert entries[-1]["seq"] == 1


def test_load_limit(hist_file):
    for i in range(5):
        history.record({"seq": i}, path=hist_file)
    entries = history.load(path=hist_file, limit=2)
    assert len(entries) == 2
    assert entries[0]["seq"] == 4


def test_load_missing_file_returns_empty(hist_file):
    assert history.load(path=hist_file) == []


def test_load_corrupt_file_returns_empty(hist_file):
    hist_file.write_text("not valid json", encoding="utf-8")
    assert history.load(path=hist_file) == []


# ---------------------------------------------------------------------------
# clear
# ---------------------------------------------------------------------------

def test_clear_removes_all_entries(hist_file):
    for i in range(3):
        history.record({"seq": i}, path=hist_file)
    history.clear(path=hist_file)
    assert history.load(path=hist_file) == []


def test_clear_on_missing_file_does_not_raise(hist_file):
    history.clear(path=hist_file)  # should not raise
    assert hist_file.exists()


# ---------------------------------------------------------------------------
# MAX_ENTRIES cap
# ---------------------------------------------------------------------------

def test_max_entries_cap(hist_file, monkeypatch):
    monkeypatch.setattr(history, "MAX_ENTRIES", 5)
    for i in range(8):
        history.record({"seq": i}, path=hist_file)
    raw = json.loads(hist_file.read_text())
    assert len(raw) == 5
    assert raw[-1]["seq"] == 7
