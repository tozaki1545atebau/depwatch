"""Tests for depwatch.dependency_graph."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from depwatch.dependency_graph import (
    DependencyNode,
    _extract_dep_name,
    _normalise,
    build_graph,
    render_json,
    render_text,
)


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

def _make_dist(name: str, version: str, requires=None):
    dist = MagicMock()
    dist.metadata = {"Name": name, "Version": version}
    dist.requires = requires
    return dist


# ---------------------------------------------------------------------------
# unit tests for helpers
# ---------------------------------------------------------------------------

def test_normalise_lowercases():
    assert _normalise("Requests") == "requests"


def test_normalise_replaces_hyphens():
    assert _normalise("my-package") == "my_package"


def test_extract_dep_name_strips_version():
    assert _extract_dep_name("requests>=2.0") == "requests"


def test_extract_dep_name_strips_extras():
    assert _extract_dep_name("uvicorn[standard]") == "uvicorn"


def test_extract_dep_name_strips_marker():
    assert _extract_dep_name("colorama; sys_platform == 'win32'") == "colorama"


# ---------------------------------------------------------------------------
# build_graph
# ---------------------------------------------------------------------------

_FAKE_DISTS = [
    _make_dist("requests", "2.31.0", ["urllib3>=1.21", "certifi>=2017.4.17"]),
    _make_dist("urllib3", "2.0.3", []),
    _make_dist("certifi", "2024.2.2", None),
]


@patch("depwatch.dependency_graph.im.distributions", return_value=_FAKE_DISTS)
def test_build_graph_includes_all_dists(mock_dists):
    graph = build_graph()
    assert "requests" in graph
    assert "urllib3" in graph
    assert "certifi" in graph


@patch("depwatch.dependency_graph.im.distributions", return_value=_FAKE_DISTS)
def test_build_graph_filters_by_name(mock_dists):
    graph = build_graph(["requests"])
    assert "requests" in graph
    assert "urllib3" not in graph


@patch("depwatch.dependency_graph.im.distributions", return_value=_FAKE_DISTS)
def test_build_graph_node_has_requires(mock_dists):
    graph = build_graph(["requests"])
    node = graph["requests"]
    assert "urllib3" in node.requires
    assert "certifi" in node.requires


@patch("depwatch.dependency_graph.im.distributions", return_value=_FAKE_DISTS)
def test_build_graph_none_requires_treated_as_empty(mock_dists):
    graph = build_graph(["certifi"])
    assert graph["certifi"].requires == []


@patch("depwatch.dependency_graph.im.distributions", return_value=_FAKE_DISTS)
def test_build_graph_unknown_package_skipped(mock_dists):
    graph = build_graph(["nonexistent"])
    assert graph == {}


# ---------------------------------------------------------------------------
# render_text
# ---------------------------------------------------------------------------

def test_render_text_empty_graph():
    assert render_text({}) == "No packages found.\n"


def test_render_text_contains_package_name():
    graph = {"requests": DependencyNode("requests", "2.31.0", ["urllib3"])}
    text = render_text(graph)
    assert "requests" in text
    assert "2.31.0" in text


def test_render_text_contains_dependency():
    graph = {"requests": DependencyNode("requests", "2.31.0", ["urllib3"])}
    text = render_text(graph)
    assert "urllib3" in text


# ---------------------------------------------------------------------------
# render_json
# ---------------------------------------------------------------------------

def test_render_json_returns_list():
    graph = {"requests": DependencyNode("requests", "2.31.0", ["urllib3"])}
    result = render_json(graph)
    assert isinstance(result, list)
    assert result[0]["name"] == "requests"
    assert "urllib3" in result[0]["requires"]


def test_render_json_sorted_by_name():
    graph = {
        "zlib": DependencyNode("zlib", "1.0", []),
        "aiohttp": DependencyNode("aiohttp", "3.9", []),
    }
    result = render_json(graph)
    assert result[0]["name"] == "aiohttp"
    assert result[1]["name"] == "zlib"
