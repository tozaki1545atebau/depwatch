"""Cache for scan summaries to avoid redundant processing."""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Optional

_DEFAULT_TTL = 300  # seconds


def _utcnow() -> float:
    return time.time()


def _cache_path(base_dir: Path) -> Path:
    return base_dir / ".depwatch_summary_cache.json"


def save(base_dir: Path, summary: dict, ttl: int = _DEFAULT_TTL) -> None:
    """Persist a summary dict with an expiry timestamp."""
    base_dir.mkdir(parents=True, exist_ok=True)
    payload = {
        "expires_at": _utcnow() + ttl,
        "summary": summary,
    }
    _cache_path(base_dir).write_text(json.dumps(payload, indent=2))


def load(base_dir: Path) -> Optional[dict]:
    """Return cached summary if still valid, otherwise None."""
    path = _cache_path(base_dir)
    if not path.exists():
        return None
    try:
        payload = json.loads(path.read_text())
        if _utcnow() < payload["expires_at"]:
            return payload["summary"]
    except (KeyError, json.JSONDecodeError, OSError):
        pass
    return None


def invalidate(base_dir: Path) -> None:
    """Remove the cache file if it exists."""
    path = _cache_path(base_dir)
    if path.exists():
        path.unlink()


def is_valid(base_dir: Path) -> bool:
    """Return True when a non-expired cache entry exists."""
    return load(base_dir) is not None
