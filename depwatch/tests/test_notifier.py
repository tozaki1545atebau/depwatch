"""Tests for depwatch.notifier."""

from __future__ import annotations

import json
import time
from pathlib import Path
from unittest.mock import patch

import pytest

from depwatch import notifier


@pytest.fixture()
def state_file(tmp_path: Path) -> Path:
    return tmp_path / "notifier_state.json"


def _write_state(path: Path, data: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data))


class TestShouldNotify:
    def test_returns_true_when_no_state_file(self, state_file: Path) -> None:
        assert notifier.should_notify("requests", state_file) is True

    def test_returns_true_when_package_not_in_state(self, state_file: Path) -> None:
        _write_state(state_file, {"other": time.time()})
        assert notifier.should_notify("requests", state_file) is True

    def test_returns_false_within_cooldown(self, state_file: Path) -> None:
        _write_state(state_file, {"requests": time.time()})
        assert notifier.should_notify("requests", state_file, cooldown=3600) is False

    def test_returns_true_after_cooldown_expires(self, state_file: Path) -> None:
        old_ts = time.time() - 7200
        _write_state(state_file, {"requests": old_ts})
        assert notifier.should_notify("requests", state_file, cooldown=3600) is True

    def test_handles_corrupt_state_file(self, state_file: Path) -> None:
        state_file.parent.mkdir(parents=True, exist_ok=True)
        state_file.write_text("not-json")
        assert notifier.should_notify("requests", state_file) is True


class TestMarkNotified:
    def test_creates_state_file(self, state_file: Path) -> None:
        notifier.mark_notified("requests", state_file)
        assert state_file.exists()

    def test_records_timestamp(self, state_file: Path) -> None:
        before = time.time()
        notifier.mark_notified("requests", state_file)
        after = time.time()
        state = json.loads(state_file.read_text())
        assert before <= state["requests"] <= after

    def test_updates_existing_entry(self, state_file: Path) -> None:
        old_ts = time.time() - 9999
        _write_state(state_file, {"requests": old_ts})
        notifier.mark_notified("requests", state_file)
        state = json.loads(state_file.read_text())
        assert state["requests"] > old_ts


class TestFilterPackages:
    def test_returns_all_when_no_state(self, state_file: Path) -> None:
        pkgs = ["requests", "flask", "numpy"]
        assert notifier.filter_packages(pkgs, state_file) == pkgs

    def test_excludes_recently_notified(self, state_file: Path) -> None:
        _write_state(state_file, {"flask": time.time()})
        result = notifier.filter_packages(["requests", "flask"], state_file, cooldown=3600)
        assert result == ["requests"]

    def test_includes_expired_cooldown(self, state_file: Path) -> None:
        _write_state(state_file, {"flask": time.time() - 7200})
        result = notifier.filter_packages(["flask"], state_file, cooldown=3600)
        assert result == ["flask"]


class TestResetPackage:
    def test_removes_package_from_state(self, state_file: Path) -> None:
        _write_state(state_file, {"requests": time.time(), "flask": time.time()})
        notifier.reset_package("requests", state_file)
        state = json.loads(state_file.read_text())
        assert "requests" not in state
        assert "flask" in state

    def test_no_error_when_package_missing(self, state_file: Path) -> None:
        _write_state(state_file, {})
        notifier.reset_package("nonexistent", state_file)  # should not raise
