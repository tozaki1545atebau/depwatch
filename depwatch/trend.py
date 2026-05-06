"""Track vulnerability and outdated-package counts over time."""

from __future__ import annotations

import json
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import List, Optional

from depwatch.scanner import ScanReport


def _utcnow() -> str:
    from datetime import datetime, timezone
    return datetime.now(timezone.utc).isoformat()


@dataclass
class TrendPoint:
    timestamp: str
    outdated_count: int
    vulnerable_count: int
    total_count: int

    def as_dict(self) -> dict:
        return asdict(self)


def _default_path() -> Path:
    return Path(".depwatch_trend.json")


def record(report: ScanReport, path: Optional[Path] = None) -> TrendPoint:
    """Append a new data point derived from *report* to the trend log."""
    target = path or _default_path()
    point = TrendPoint(
        timestamp=_utcnow(),
        outdated_count=len(report.outdated()),
        vulnerable_count=len(report.vulnerable()),
        total_count=len(report.results),
    )
    raw: List[dict] = []
    if target.exists():
        raw = json.loads(target.read_text())
    raw.append(point.as_dict())
    target.write_text(json.dumps(raw, indent=2))
    return point


def load(path: Optional[Path] = None, limit: int = 0) -> List[TrendPoint]:
    """Return recorded trend points, newest first.  *limit* caps the result."""
    target = path or _default_path()
    if not target.exists():
        return []
    raw: List[dict] = json.loads(target.read_text())
    points = [TrendPoint(**d) for d in reversed(raw)]
    return points[:limit] if limit > 0 else points


def summarise(points: List[TrendPoint]) -> dict:
    """Return basic statistics across *points*."""
    if not points:
        return {"count": 0}
    outdated = [p.outdated_count for p in points]
    vulnerable = [p.vulnerable_count for p in points]
    return {
        "count": len(points),
        "outdated": {"min": min(outdated), "max": max(outdated), "latest": outdated[0]},
        "vulnerable": {"min": min(vulnerable), "max": max(vulnerable), "latest": vulnerable[0]},
    }
