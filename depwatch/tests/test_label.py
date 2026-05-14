"""Tests for depwatch.label and depwatch.label_reporter."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from depwatch.label import add_label, remove_label, get_labels, packages_with_label, all_labels
from depwatch.label_reporter import render_text, render_json, render


@pytest.fixture()
def label_file(tmp_path) -> Path:
    return tmp_path / "labels.json"


# ---------------------------------------------------------------------------
# add_label
# ---------------------------------------------------------------------------

def test_add_label_creates_file(label_file):
    add_label("requests", "web", path=label_file)
    assert label_file.exists()


def test_add_label_stores_label(label_file):
    add_label("requests", "web", path=label_file)
    assert "web" in get_labels("requests", path=label_file)


def test_add_label_no_duplicates(label_file):
    add_label("requests", "web", path=label_file)
    add_label("requests", "web", path=label_file)
    assert get_labels("requests", path=label_file).count("web") == 1


def test_add_multiple_labels(label_file):
    add_label("requests", "web", path=label_file)
    add_label("requests", "core", path=label_file)
    labels = get_labels("requests", path=label_file)
    assert "web" in labels and "core" in labels


# ---------------------------------------------------------------------------
# remove_label
# ---------------------------------------------------------------------------

def test_remove_label_removes_entry(label_file):
    add_label("requests", "web", path=label_file)
    remove_label("requests", "web", path=label_file)
    assert "web" not in get_labels("requests", path=label_file)


def test_remove_label_cleans_empty_package(label_file):
    add_label("requests", "web", path=label_file)
    remove_label("requests", "web", path=label_file)
    data = all_labels(path=label_file)
    assert "requests" not in data


def test_remove_label_noop_when_absent(label_file):
    # Should not raise
    remove_label("requests", "ghost", path=label_file)


# ---------------------------------------------------------------------------
# get_labels / packages_with_label
# ---------------------------------------------------------------------------

def test_get_labels_returns_empty_for_unknown(label_file):
    assert get_labels("unknown", path=label_file) == []


def test_packages_with_label_returns_correct_packages(label_file):
    add_label("requests", "web", path=label_file)
    add_label("flask", "web", path=label_file)
    add_label("numpy", "science", path=label_file)
    result = packages_with_label("web", path=label_file)
    assert set(result) == {"requests", "flask"}


def test_packages_with_label_empty_when_none(label_file):
    assert packages_with_label("nonexistent", path=label_file) == []


# ---------------------------------------------------------------------------
# label_reporter
# ---------------------------------------------------------------------------

def test_render_text_no_labels():
    assert render_text(data={}) == "No labels defined."


def test_render_text_contains_package_name():
    output = render_text(data={"requests": ["web"]})
    assert "requests" in output


def test_render_text_contains_label():
    output = render_text(data={"requests": ["web"]})
    assert "web" in output


def test_render_text_shows_count():
    output = render_text(data={"requests": ["web"], "flask": ["web"]})
    assert "2" in output


def test_render_json_is_valid(label_file):
    add_label("requests", "web", path=label_file)
    raw = render_json(path=label_file)
    parsed = json.loads(raw)
    assert "requests" in parsed


def test_render_dispatches_json():
    out = render(fmt="json", data={"a": ["b"]})
    assert json.loads(out) == {"a": ["b"]}


def test_render_dispatches_text():
    out = render(fmt="text", data={"a": ["b"]})
    assert "a" in out
