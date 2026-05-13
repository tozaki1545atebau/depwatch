"""Tests for depwatch.digest"""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from unittest.mock import patch

import pytest

from depwatch.digest import build_digest, render_text, render_json, render, _points_in_window
from depwatch.trend import TrendPoint


def _ts(days_ago: float = 0) -> datetime:
    return datetime.now(timezone.utc) - timedelta(days=days_ago)


def _point(outdated: int, vulnerable: int, days_ago: float = 0) -> TrendPoint:
    return TrendPoint(timestamp=_ts(days_ago), outdated_count=outdated, vulnerable_count=vulnerable, total_count=10)


@pytest.fixture()
def sample_points():
    return [
        _point(3, 2, days_ago=6),
        _point(4, 3, days_ago=4),
        _point(2, 1, days_ago=2),
        _point(1, 0, days_ago=0),
    ]


@pytest.fixture()
def sample_history():
    return [
        {"timestamp": _ts(1).isoformat(), "summary": "ok"},
        {"timestamp": _ts(3).isoformat(), "summary": "ok"},
        {"timestamp": _ts(10).isoformat(), "summary": "old"},  # outside 7-day window
    ]


def test_points_in_window_filters_old(sample_points):
    recent = _points_in_window(sample_points, days=3)
    assert all(p.timestamp >= datetime.now(timezone.utc) - timedelta(days=3) for p in recent)


def test_points_in_window_includes_all_within_window(sample_points):
    all_pts = _points_in_window(sample_points, days=30)
    assert len(all_pts) == len(sample_points)


def test_build_digest_no_data_returns_no_data_trend():
    with patch("depwatch.digest.load_trend", return_value=[]), \
         patch("depwatch.digest.load_history", return_value=[]):
        result = build_digest(days=7)
    assert result["trend"] == "no_data"
    assert result["data_points"] == 0


def test_build_digest_counts_data_points(sample_points, sample_history):
    with patch("depwatch.digest.load_trend", return_value=sample_points), \
         patch("depwatch.digest.load_history", return_value=sample_history):
        result = build_digest(days=7)
    assert result["data_points"] == 4


def test_build_digest_scan_count_excludes_old(sample_points, sample_history):
    with patch("depwatch.digest.load_trend", return_value=sample_points), \
         patch("depwatch.digest.load_history", return_value=sample_history):
        result = build_digest(days=7)
    assert result["scan_count"] == 2  # only 2 within 7 days


def test_build_digest_averages(sample_points, sample_history):
    with patch("depwatch.digest.load_trend", return_value=sample_points), \
         patch("depwatch.digest.load_history", return_value=sample_history):
        result = build_digest(days=7)
    assert result["avg_outdated"] == round((3 + 4 + 2 + 1) / 4, 2)
    assert result["avg_vulnerable"] == round((2 + 3 + 1 + 0) / 4, 2)


def test_build_digest_max_values(sample_points, sample_history):
    with patch("depwatch.digest.load_trend", return_value=sample_points), \
         patch("depwatch.digest.load_history", return_value=sample_history):
        result = build_digest(days=7)
    assert result["max_outdated"] == 4
    assert result["max_vulnerable"] == 3


def test_improving_trend():
    pts = [_point(5, 5, days_ago=6), _point(5, 4, days_ago=5), _point(1, 0, days_ago=1), _point(1, 0, days_ago=0)]
    with patch("depwatch.digest.load_trend", return_value=pts), \
         patch("depwatch.digest.load_history", return_value=[]):
        result = build_digest(days=7)
    assert result["trend"] == "improving"


def test_worsening_trend():
    pts = [_point(1, 0, days_ago=6), _point(1, 0, days_ago=5), _point(5, 5, days_ago=1), _point(5, 5, days_ago=0)]
    with patch("depwatch.digest.load_trend", return_value=pts), \
         patch("depwatch.digest.load_history", return_value=[]):
        result = build_digest(days=7)
    assert result["trend"] == "worsening"


def test_render_text_contains_trend(sample_points, sample_history):
    with patch("depwatch.digest.load_trend", return_value=sample_points), \
         patch("depwatch.digest.load_history", return_value=sample_history):
        digest = build_digest(days=7)
    text = render_text(digest)
    assert "STABLE" in text or "IMPROVING" in text or "WORSENING" in text or "NO_DATA" in text
    assert "Depwatch Digest" in text


def test_render_json_is_valid(sample_points, sample_history):
    with patch("depwatch.digest.load_trend", return_value=sample_points), \
         patch("depwatch.digest.load_history", return_value=sample_history):
        digest = build_digest(days=7)
    parsed = json.loads(render_json(digest))
    assert parsed["period_days"] == 7


def test_render_dispatches_to_json(sample_points, sample_history):
    with patch("depwatch.digest.load_trend", return_value=sample_points), \
         patch("depwatch.digest.load_history", return_value=sample_history):
        digest = build_digest(days=7)
    output = render(digest, fmt="json")
    assert output.startswith("{")


def test_render_dispatches_to_text(sample_points, sample_history):
    with patch("depwatch.digest.load_trend", return_value=sample_points), \
         patch("depwatch.digest.load_history", return_value=sample_history):
        digest = build_digest(days=7)
    output = render(digest, fmt="text")
    assert "Digest" in output
