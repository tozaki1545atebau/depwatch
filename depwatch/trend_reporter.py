"""Render trend data as human-readable text or JSON."""

from __future__ import annotations

import json
from typing import List

from depwatch.trend import TrendPoint, summarise

_SEP = "-" * 52


def render_text(points: List[TrendPoint]) -> str:
    """Return a formatted text table of *points* plus a summary footer."""
    if not points:
        return "No trend data available.\n"

    lines: List[str] = [
        _SEP,
        f"{'Timestamp':<35} {'Outdated':>8} {'Vuln':>6} {'Total':>6}",
        _SEP,
    ]
    for p in points:
        lines.append(
            f"{p.timestamp:<35} {p.outdated_count:>8} {p.vulnerable_count:>6} {p.total_count:>6}"
        )

    stats = summarise(points)
    lines += [
        _SEP,
        f"Entries shown : {stats['count']}",
        f"Outdated      : min={stats['outdated']['min']}  max={stats['outdated']['max']}  latest={stats['outdated']['latest']}",
        f"Vulnerable    : min={stats['vulnerable']['min']}  max={stats['vulnerable']['max']}  latest={stats['vulnerable']['latest']}",
        _SEP,
    ]
    return "\n".join(lines) + "\n"


def render_json(points: List[TrendPoint]) -> str:
    """Return JSON with the raw points and a summary block."""
    payload = {
        "summary": summarise(points),
        "points": [p.as_dict() for p in points],
    }
    return json.dumps(payload, indent=2)


def render(points: List[TrendPoint], fmt: str = "text") -> str:
    """Dispatch to *render_text* or *render_json* based on *fmt*."""
    if fmt == "json":
        return render_json(points)
    if fmt == "text":
        return render_text(points)
    raise ValueError(f"Unknown format: {fmt!r}. Choose 'text' or 'json'.")
