"""Package labelling — attach user-defined tags to packages and query them."""

from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional

_DEFAULT_PATH = Path(".depwatch") / "labels.json"


def _utcnow() -> str:
    return datetime.now(timezone.utc).isoformat()


def _load_raw(path: Path) -> Dict[str, List[str]]:
    if not path.exists():
        return {}
    with path.open() as fh:
        return json.load(fh)


def _save_raw(data: Dict[str, List[str]], path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w") as fh:
        json.dump(data, fh, indent=2)


def add_label(package: str, label: str, path: Optional[Path] = None) -> None:
    """Attach *label* to *package*.  Duplicate labels are silently ignored."""
    p = path or _DEFAULT_PATH
    data = _load_raw(p)
    labels = data.setdefault(package, [])
    if label not in labels:
        labels.append(label)
    _save_raw(data, p)


def remove_label(package: str, label: str, path: Optional[Path] = None) -> None:
    """Remove *label* from *package*.  No-op if the label is not present."""
    p = path or _DEFAULT_PATH
    data = _load_raw(p)
    if package in data:
        data[package] = [l for l in data[package] if l != label]
        if not data[package]:
            del data[package]
    _save_raw(data, p)


def get_labels(package: str, path: Optional[Path] = None) -> List[str]:
    """Return all labels attached to *package* (may be empty)."""
    p = path or _DEFAULT_PATH
    data = _load_raw(p)
    return list(data.get(package, []))


def packages_with_label(label: str, path: Optional[Path] = None) -> List[str]:
    """Return all packages that carry *label*."""
    p = path or _DEFAULT_PATH
    data = _load_raw(p)
    return [pkg for pkg, labels in data.items() if label in labels]


def all_labels(path: Optional[Path] = None) -> Dict[str, List[str]]:
    """Return the full label mapping."""
    p = path or _DEFAULT_PATH
    return _load_raw(p)
