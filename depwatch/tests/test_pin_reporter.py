"""Tests for depwatch.pin_reporter."""
from __future__ import annotations

import json

import pytest

from depwatch.pin_reporter import render, render_json, render_text

_DRIFTS = [
    {"package": "requests", "installed": "2.31.0", "pinned": "2.28.0"},
    {"package": "flask", "installed": "3.0.0", "pinned": "2.3.3"},
]


def test_render_text_no_drift():
    output = render_text([])
    assert "No version drift" in output


def test_render_text_contains_package_name():
    output = render_text(_DRIFTS)
    assert "requests" in output
    assert "flask" in output


def test_render_text_contains_installed_version():
    output = render_text(_DRIFTS)
    assert "2.31.0" in output


def test_render_text_contains_pinned_version():
    output = render_text(_DRIFTS)
    assert "2.28.0" in output


def test_render_text_shows_count():
    output = render_text(_DRIFTS)
    assert "2" in output


def test_render_json_is_valid_json():
    output = render_json(_DRIFTS)
    data = json.loads(output)
    assert isinstance(data, dict)


def test_render_json_count_field():
    data = json.loads(render_json(_DRIFTS))
    assert data["count"] == 2


def test_render_json_drifts_field():
    data = json.loads(render_json(_DRIFTS))
    assert len(data["drifts"]) == 2


def test_render_json_empty():
    data = json.loads(render_json([]))
    assert data["count"] == 0
    assert data["drifts"] == []


def test_render_dispatches_text():
    output = render(_DRIFTS, fmt="text")
    assert "Drift" in output


def test_render_dispatches_json():
    output = render(_DRIFTS, fmt="json")
    data = json.loads(output)
    assert "drifts" in data


def test_render_defaults_to_text():
    output = render(_DRIFTS)
    assert "pinned" in output.lower()
