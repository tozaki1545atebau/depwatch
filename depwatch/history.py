"""Persistent scan history: store and retrieve past ScanReport summaries."""

from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional

DEFAULT_HISTORY_PATH = Path(os.environ.get("DEPWATCH_HISTORY_FILE", ".depwatch_history.json"))
MAX_ENTRIES = 500


def _utcnow() -> str:
    return datetime.now(timezone.utc).isoformat()


def _load_raw(path: Path) -> List[dict]:
    if not path.exists():
        return []
    try:
        with path.open("r", encoding="utf-8") as fh:
            data = json.load(fh)
        return data if isinstance(data, list) else []
    except (json.JSONDecodeError, OSError):
        return []


def _save_raw(entries: List[dict], path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as fh:
        json.dump(entries, fh, indent=2)


def record(report_summary: dict, path: Path = DEFAULT_HISTORY_PATH) -> None:
    """Append a timestamped summary entry to the history file."""
    entries = _load_raw(path)
    entry = {"recorded_at": _utcnow(), **report_summary}
    entries.append(entry)
    if len(entries) > MAX_ENTRIES:
        entries = entries[-MAX_ENTRIES:]
    _save_raw(entries, path)


def load(path: Path = DEFAULT_HISTORY_PATH, limit: Optional[int] = None) -> List[dict]:
    """Return history entries, newest first, optionally limited."""
    entries = _load_raw(path)
    entries = list(reversed(entries))
    if limit is not None:
        entries = entries[:limit]
    return entries


def clear(path: Path = DEFAULT_HISTORY_PATH) -> None:
    """Remove all history entries."""
    _save_raw([], path)
