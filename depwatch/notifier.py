"""Rate-limited notification tracker to avoid alert fatigue."""

from __future__ import annotations

import json
import os
import time
from pathlib import Path
from typing import Dict, Optional

DEFAULT_COOLDOWN_SECONDS = 3600  # 1 hour


def _utcnow() -> float:
    return time.time()


def _load_state(path: Path) -> Dict[str, float]:
    """Load notification timestamps keyed by package name."""
    if not path.exists():
        return {}
    try:
        return json.loads(path.read_text())
    except (json.JSONDecodeError, OSError):
        return {}


def _save_state(path: Path, state: Dict[str, float]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(state, indent=2))


def should_notify(
    package: str,
    state_path: Path,
    cooldown: int = DEFAULT_COOLDOWN_SECONDS,
) -> bool:
    """Return True if enough time has passed since the last alert for *package*."""
    state = _load_state(state_path)
    last_sent = state.get(package)
    if last_sent is None:
        return True
    return (_utcnow() - last_sent) >= cooldown


def mark_notified(
    package: str,
    state_path: Path,
) -> None:
    """Record that a notification was just sent for *package*."""
    state = _load_state(state_path)
    state[package] = _utcnow()
    _save_state(state_path, state)


def filter_packages(
    packages: list[str],
    state_path: Path,
    cooldown: int = DEFAULT_COOLDOWN_SECONDS,
) -> list[str]:
    """Return only packages that are eligible for a new notification."""
    return [p for p in packages if should_notify(p, state_path, cooldown)]


def reset_package(package: str, state_path: Path) -> None:
    """Remove cooldown state for *package*, forcing next check to notify."""
    state = _load_state(state_path)
    state.pop(package, None)
    _save_state(state_path, state)
