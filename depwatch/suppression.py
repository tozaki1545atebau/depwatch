"""CVE suppression list — ignore known/accepted vulnerabilities."""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

_DEFAULT_PATH = Path(".depwatch_suppressions.json")


def _utcnow() -> str:
    return datetime.now(timezone.utc).isoformat()


def _load_raw(path: Path) -> dict:
    if not path.exists():
        return {}
    with path.open() as fh:
        return json.load(fh)


def _save_raw(data: dict, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w") as fh:
        json.dump(data, fh, indent=2)


def suppress(
    cve_id: str,
    reason: str,
    expires: Optional[str] = None,
    path: Path = _DEFAULT_PATH,
) -> None:
    """Add *cve_id* to the suppression list with an optional expiry (ISO-8601)."""
    data = _load_raw(path)
    data[cve_id] = {"reason": reason, "suppressed_at": _utcnow(), "expires": expires}
    _save_raw(data, path)


def unsuppress(cve_id: str, path: Path = _DEFAULT_PATH) -> bool:
    """Remove *cve_id* from the suppression list. Returns True if it existed."""
    data = _load_raw(path)
    if cve_id not in data:
        return False
    del data[cve_id]
    _save_raw(data, path)
    return True


def is_suppressed(cve_id: str, path: Path = _DEFAULT_PATH) -> bool:
    """Return True if *cve_id* is actively suppressed (not expired)."""
    data = _load_raw(path)
    entry = data.get(cve_id)
    if entry is None:
        return False
    expires = entry.get("expires")
    if expires is not None:
        expiry_dt = datetime.fromisoformat(expires)
        if expiry_dt.tzinfo is None:
            expiry_dt = expiry_dt.replace(tzinfo=timezone.utc)
        if datetime.now(timezone.utc) >= expiry_dt:
            return False
    return True


def load_all(path: Path = _DEFAULT_PATH) -> dict:
    """Return the raw suppression dict (all entries, including expired)."""
    return _load_raw(path)
