"""Tests for depwatch.cached_scanner."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

import pytest

import depwatch.summary_cache as sc
from depwatch.cached_scanner import invalidate, scan_with_cache
from depwatch.checker import CheckResult, PackageStatus
from depwatch.cve import CVEResult


def _make_result(name: str, status: PackageStatus = PackageStatus.OK) -> CheckResult:
    return CheckResult(
        package=name,
        installed="1.0.0",
        latest="1.0.0" if status == PackageStatus.OK else "2.0.0",
        status=status,
        cve=CVEResult(package=name, vulnerabilities=[]),
    )


@pytest.fixture()
def cache_dir(tmp_path: Path) -> Path:
    return tmp_path / "cache"


def test_scan_populates_cache(cache_dir: Path) -> None:
    results = [_make_result("requests")]
    scan_with_cache(results, cache_dir=cache_dir, ttl=60)
    assert sc.is_valid(cache_dir)


def test_scan_returns_false_from_cache_on_first_run(cache_dir: Path) -> None:
    results = [_make_result("requests")]
    _, from_cache = scan_with_cache(results, cache_dir=cache_dir)
    assert from_cache is False


def test_scan_returns_true_from_cache_on_second_run(cache_dir: Path) -> None:
    results = [_make_result("requests")]
    scan_with_cache(results, cache_dir=cache_dir, ttl=60)
    _, from_cache = scan_with_cache(results, cache_dir=cache_dir, ttl=60)
    assert from_cache is True


def test_force_bypasses_cache(cache_dir: Path) -> None:
    results = [_make_result("requests")]
    scan_with_cache(results, cache_dir=cache_dir, ttl=60)
    _, from_cache = scan_with_cache(results, cache_dir=cache_dir, ttl=60, force=True)
    assert from_cache is False


def test_report_contains_results(cache_dir: Path) -> None:
    results = [_make_result("flask"), _make_result("django")]
    report, _ = scan_with_cache(results, cache_dir=cache_dir)
    assert report.total == 2


def test_invalidate_clears_cache(cache_dir: Path) -> None:
    results = [_make_result("requests")]
    scan_with_cache(results, cache_dir=cache_dir, ttl=60)
    invalidate(cache_dir)
    assert not sc.is_valid(cache_dir)


def test_expired_cache_triggers_fresh_scan(cache_dir: Path) -> None:
    results = [_make_result("requests")]
    with patch.object(sc, "_utcnow", return_value=1_000.0):
        scan_with_cache(results, cache_dir=cache_dir, ttl=10)
    with patch.object(sc, "_utcnow", return_value=1_100.0):
        _, from_cache = scan_with_cache(results, cache_dir=cache_dir, ttl=10)
    assert from_cache is False
