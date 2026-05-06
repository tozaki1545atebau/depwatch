"""Baseline management: snapshot current package states to suppress known issues."""

from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from depwatch.scanner import ScanReport

_DEFAULT_PATH = Path("depwatch_baseline.json")


def _utcnow() -> str:
    return datetime.now(timezone.utc).isoformat()


def _report_to_baseline(report: ScanReport) -> dict[str, Any]:
    """Convert a ScanReport into a serialisable baseline dict."""
    packages: dict[str, Any] = {}
    for result in report.results:
        entry: dict[str, Any] = {
            "installed": result.installed_version,
            "latest": result.latest_version,
            "cve_ids": [v.cve_id for v in (result.cve_result.vulnerabilities if result.cve_result else [])],
        }
        packages[result.package_name] = entry
    return {"created_at": _utcnow(), "packages": packages}


def save(report: ScanReport, path: Path = _DEFAULT_PATH) -> None:
    """Persist a baseline snapshot derived from *report* to *path*."""
    data = _report_to_baseline(report)
    path.write_text(json.dumps(data, indent=2), encoding="utf-8")


def load(path: Path = _DEFAULT_PATH) -> dict[str, Any]:
    """Return the raw baseline dict, or an empty structure when absent."""
    if not path.exists():
        return {"created_at": None, "packages": {}}
    return json.loads(path.read_text(encoding="utf-8"))


def is_new_issue(package: str, installed: str, cve_ids: list[str],
                baseline: dict[str, Any]) -> bool:
    """Return True when *package* has issues not captured in *baseline*."""
    pkg = baseline.get("packages", {}).get(package)
    if pkg is None:
        return bool(cve_ids) or False
    known_cves: set[str] = set(pkg.get("cve_ids", []))
    new_cves = set(cve_ids) - known_cves
    return bool(new_cves)
