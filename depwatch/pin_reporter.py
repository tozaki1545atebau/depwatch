"""Render drift reports from pin comparisons."""
from __future__ import annotations

import json
from typing import Sequence


def render_text(drifts: Sequence[dict]) -> str:
    """Return a human-readable drift summary."""
    if not drifts:
        return "No version drift detected — all packages match their pins.\n"

    lines = ["Version Drift Report", "=" * 40]
    for d in drifts:
        lines.append(
            f"  {d['package']}: installed={d['installed']}  pinned={d['pinned']}"
        )
    lines.append("")
    lines.append(f"Drifted packages: {len(drifts)}")
    return "\n".join(lines) + "\n"


def render_json(drifts: Sequence[dict]) -> str:
    """Return drift data as a JSON string."""
    return json.dumps({"drifts": list(drifts), "count": len(drifts)}, indent=2)


def render(drifts: Sequence[dict], fmt: str = "text") -> str:
    """Dispatch to the appropriate renderer."""
    if fmt == "json":
        return render_json(drifts)
    return render_text(drifts)
