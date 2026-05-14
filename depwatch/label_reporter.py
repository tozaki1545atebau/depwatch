"""Render the label registry as human-readable text or JSON."""

from __future__ import annotations

import json
from typing import Dict, List

from depwatch.label import all_labels
from pathlib import Path
from typing import Optional


def render_text(data: Optional[Dict[str, List[str]]] = None, path: Optional[Path] = None) -> str:
    """Return a plain-text table of package → labels."""
    mapping = data if data is not None else all_labels(path)
    if not mapping:
        return "No labels defined."
    lines = ["Package Labels", "=" * 40]
    for pkg in sorted(mapping):
        labels = ", ".join(sorted(mapping[pkg])) if mapping[pkg] else "(none)"
        lines.append(f"  {pkg:<30} {labels}")
    lines.append("")
    lines.append(f"Total packages labelled: {len(mapping)}")
    return "\n".join(lines)


def render_json(data: Optional[Dict[str, List[str]]] = None, path: Optional[Path] = None) -> str:
    """Return a JSON string of the label mapping."""
    mapping = data if data is not None else all_labels(path)
    return json.dumps(mapping, indent=2)


def render(fmt: str = "text", data: Optional[Dict[str, List[str]]] = None, path: Optional[Path] = None) -> str:
    if fmt == "json":
        return render_json(data, path)
    return render_text(data, path)
