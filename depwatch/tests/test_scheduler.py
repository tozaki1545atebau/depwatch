"""Tests for depwatch.scheduler."""

import time
from unittest.mock import MagicMock, patch

import pytest

from depwatch.scheduler import Scheduler


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _fast_scheduler(callback, interval: int = 60) -> Scheduler:
    """Return a Scheduler whose _sleep is a no-op so tests run instantly."""
    s = Scheduler(interval_seconds=interval, callback=callback)
    s._sleep = MagicMock()  # skip real sleep
    return s


# ---------------------------------------------------------------------------
# Construction
# ---------------------------------------------------------------------------

def test_invalid_interval_raises():
    with pytest.raises(ValueError, match="positive"):
        Scheduler(interval_seconds=0, callback=lambda: None)


def test_initial_tick_count_is_zero():
    s = Scheduler(interval_seconds=10, callback=lambda: None)
    assert s.tick_count == 0


# ---------------------------------------------------------------------------
# Single-tick behaviour
# ---------------------------------------------------------------------------

def test_callback_called_on_tick():
    cb = MagicMock()
    s = _fast_scheduler(cb)
    s._run_once()
    cb.assert_called_once()
    assert s.tick_count == 1


def test_exception_in_callback_does_not_propagate():
    def _bad():
        raise RuntimeError("boom")

    s = _fast_scheduler(_bad)
    s._run_once()  # should not raise
    assert s.tick_count == 1


# ---------------------------------------------------------------------------
# start / stop
# ---------------------------------------------------------------------------

def test_stop_prevents_further_ticks():
    call_count = 0

    def _cb():
        nonlocal call_count
        call_count += 1

    s = _fast_scheduler(_cb, interval=1)

    original_sleep = s._sleep

    def _stop_after_first(_seconds):
        s.stop()

    s._sleep = _stop_after_first

    with patch.object(s, "_register_signals"):
        s.start()

    assert call_count == 1
    assert s.tick_count == 1


def test_tick_count_increments_across_multiple_runs():
    s = _fast_scheduler(MagicMock())
    for _ in range(5):
        s._run_once()
    assert s.tick_count == 5
