"""Weekly/periodic digest report aggregating trend data and scan history."""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from typing import Optional

from depwatch.trend import TrendPoint, load as load_trend
from depwatch.history import load as load_history


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _points_in_window(points: list[TrendPoint], days: int) -> list[TrendPoint]:
    cutoff = _utcnow() - timedelta(days=days)
    return [p for p in points if p.timestamp >= cutoff]


def build_digest(trend_path: Optional[str] = None, history_path: Optional[str] = None, days: int = 7) -> dict:
    """Aggregate scan trend and history into a digest summary for the given window."""
    points = load_trend(trend_path) if trend_path else load_trend()
    window = _points_in_window(points, days)

    if not window:
        return {
            "period_days": days,
            "data_points": 0,
            "avg_outdated": 0,
            "avg_vulnerable": 0,
            "max_outdated": 0,
            "max_vulnerable": 0,
            "trend": "no_data",
        }

    outdated_vals = [p.outdated_count for p in window]
    vuln_vals = [p.vulnerable_count for p in window]

    avg_outdated = sum(outdated_vals) / len(outdated_vals)
    avg_vulnerable = sum(vuln_vals) / len(vuln_vals)

    # Simple trend: compare first half avg vs second half avg of vulnerable count
    mid = max(1, len(vuln_vals) // 2)
    first_half_avg = sum(vuln_vals[:mid]) / mid
    second_half_avg = sum(vuln_vals[mid:]) / max(1, len(vuln_vals) - mid)

    if second_half_avg > first_half_avg + 0.5:
        trend = "worsening"
    elif second_half_avg < first_half_avg - 0.5:
        trend = "improving"
    else:
        trend = "stable"

    history = load_history(history_path) if history_path else load_history()
    recent_scans = [e for e in history if datetime.fromisoformat(e["timestamp"]) >= (_utcnow() - timedelta(days=days))]

    return {
        "period_days": days,
        "data_points": len(window),
        "scan_count": len(recent_scans),
        "avg_outdated": round(avg_outdated, 2),
        "avg_vulnerable": round(avg_vulnerable, 2),
        "max_outdated": max(outdated_vals),
        "max_vulnerable": max(vuln_vals),
        "trend": trend,
    }


def render_text(digest: dict) -> str:
    lines = [
        f"=== Depwatch Digest (last {digest['period_days']} days) ===",
        f"Scans recorded   : {digest.get('scan_count', 'n/a')}",
        f"Trend data points: {digest['data_points']}",
        f"Avg outdated     : {digest['avg_outdated']}",
        f"Avg vulnerable   : {digest['avg_vulnerable']}",
        f"Max outdated     : {digest['max_outdated']}",
        f"Max vulnerable   : {digest['max_vulnerable']}",
        f"Overall trend    : {digest['trend'].upper()}",
    ]
    return "\n".join(lines)


def render_json(digest: dict) -> str:
    return json.dumps(digest, indent=2)


def render(digest: dict, fmt: str = "text") -> str:
    if fmt == "json":
        return render_json(digest)
    return render_text(digest)
