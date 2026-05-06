"""Tests for depwatch.trend_reporter."""

from __future__ import annotations

import json
from typing import List

import pytest

from depwatch.trend import TrendPoint
from depwatch.trend_reporter import render, render_json, render_text


def _points(n: int = 2) -> List[TrendPoint]:
    return [
        TrendPoint(
            timestamp=f"2024-06-0{i + 1}T10:00:00+00:00",
            outdated_count=i,
            vulnerable_count=i + 1,
            total_count=10,
        )
        for i in range(n)
    ]


class TestRenderText:
    def test_empty_returns_message(self) -> None:
        out = render_text([])
        assert "No trend data" in out

    def test_contains_header_columns(self) -> None:
        out = render_text(_points())
        assert "Outdated" in out
        assert "Vuln" in out
        assert "Total" in out

    def test_contains_timestamps(self) -> None:
        pts = _points()
        out = render_text(pts)
        for p in pts:
            assert p.timestamp in out

    def test_contains_summary_footer(self) -> None:
        out = render_text(_points())
        assert "latest=" in out
        assert "Entries shown" in out

    def test_row_count_matches_points(self) -> None:
        pts = _points(3)
        out = render_text(pts)
        # Each timestamp appears exactly once in a data row
        for p in pts:
            assert out.count(p.timestamp) == 1


class TestRenderJson:
    def test_output_is_valid_json(self) -> None:
        out = render_json(_points())
        parsed = json.loads(out)
        assert isinstance(parsed, dict)

    def test_contains_points_key(self) -> None:
        parsed = json.loads(render_json(_points()))
        assert "points" in parsed
        assert len(parsed["points"]) == 2

    def test_contains_summary_key(self) -> None:
        parsed = json.loads(render_json(_points()))
        assert "summary" in parsed
        assert parsed["summary"]["count"] == 2

    def test_empty_points_summary_count_zero(self) -> None:
        parsed = json.loads(render_json([]))
        assert parsed["summary"] == {"count": 0}
        assert parsed["points"] == []


class TestRender:
    def test_text_format_dispatches(self) -> None:
        out = render(_points(), fmt="text")
        assert "Outdated" in out

    def test_json_format_dispatches(self) -> None:
        out = render(_points(), fmt="json")
        json.loads(out)  # must not raise

    def test_unknown_format_raises(self) -> None:
        with pytest.raises(ValueError, match="Unknown format"):
            render(_points(), fmt="csv")
