"""Snooze support — temporarily silence alerts for a package/CVE pair."""

from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

_DEFAULT_PATH = Path(".depwatch_snooze.json")


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _load_raw(path: Path) -> dict:
    if not path.exists():
        return {}
    with path.open() as fh:
        return json.load(fh)


def _save_raw(data: dict, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w") as fh:
        json.dump(data, fh, indent=2)


def _key(package: str, cve_id: str) -> str:
    return f"{package}::{cve_id}"


def snooze(
    package: str,
    cve_id: str,
    until: datetime,
    path: Path = _DEFAULT_PATH,
) -> None:
    """Snooze alerts for *package*/*cve_id* until *until* (UTC-aware datetime)."""
    data = _load_raw(path)
    data[_key(package, cve_id)] = until.isoformat()
    _save_raw(data, path)


def unsnooze(
    package: str,
    cve_id: str,
    path: Path = _DEFAULT_PATH,
) -> None:
    """Remove an active snooze entry."""
    data = _load_raw(path)
    data.pop(_key(package, cve_id), None)
    _save_raw(data, path)


def is_snoozed(
    package: str,
    cve_id: str,
    path: Path = _DEFAULT_PATH,
    *,
    now: Optional[datetime] = None,
) -> bool:
    """Return True if the package/CVE pair is currently snoozed."""
    data = _load_raw(path)
    raw = data.get(_key(package, cve_id))
    if raw is None:
        return False
    until = datetime.fromisoformat(raw)
    reference = now if now is not None else _utcnow()
    return reference < until


def active_snoozes(
    path: Path = _DEFAULT_PATH,
    *,
    now: Optional[datetime] = None,
) -> dict[str, datetime]:
    """Return a mapping of key -> expiry for all currently active snoozes."""
    data = _load_raw(path)
    reference = now if now is not None else _utcnow()
    return {
        k: datetime.fromisoformat(v)
        for k, v in data.items()
        if reference < datetime.fromisoformat(v)
    }
