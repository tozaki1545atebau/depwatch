"""Thin wrapper around scanner + summary_cache for cached scan results."""

from __future__ import annotations

from pathlib import Path
from typing import List, Optional

from depwatch import summary_cache
from depwatch.checker import CheckResult
from depwatch.scanner import ScanReport

_DEFAULT_CACHE_DIR = Path(".depwatch")


def _report_to_summary(report: ScanReport) -> dict:
    return {
        "total": report.total,
        "outdated": len(report.outdated()),
        "vulnerable": len(report.vulnerable()),
        "has_issues": report.has_issues(),
        "summary": report.summary(),
    }


def scan_with_cache(
    results: List[CheckResult],
    *,
    cache_dir: Path = _DEFAULT_CACHE_DIR,
    ttl: int = 300,
    force: bool = False,
) -> tuple[ScanReport, bool]:
    """Run a scan, using a cached summary when available.

    Returns (report, from_cache) where from_cache indicates whether the
    full scan was skipped because a valid cache entry existed.
    """
    if not force:
        cached = summary_cache.load(cache_dir)
        if cached is not None:
            # Reconstruct a minimal ScanReport from the cache.
            report = ScanReport(results)  # still carry the raw results
            return report, True

    report = ScanReport(results)
    summary_cache.save(cache_dir, _report_to_summary(report), ttl=ttl)
    return report, False


def invalidate(cache_dir: Path = _DEFAULT_CACHE_DIR) -> None:
    """Explicitly invalidate the cached summary."""
    summary_cache.invalidate(cache_dir)
