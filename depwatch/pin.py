"""Pin management: record and compare pinned package versions."""
from __future__ import annotations

import json
import pathlib
from datetime import datetime, timezone
from typing import Optional

from depwatch.scanner import ScanReport

_DEFAULT_PATH = pathlib.Path(".depwatch_pins.json")


def _utcnow() -> str:
    return datetime.now(timezone.utc).isoformat()


def _load_raw(path: pathlib.Path) -> dict:
    if not path.exists():
        return {}
    with path.open() as fh:
        return json.load(fh)


def _save_raw(data: dict, path: pathlib.Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w") as fh:
        json.dump(data, fh, indent=2)


def pin(report: ScanReport, path: pathlib.Path = _DEFAULT_PATH) -> None:
    """Persist the currently installed versions as the pinned baseline."""
    data = _load_raw(path)
    ts = _utcnow()
    for result in report.results:
        data[result.package] = {
            "pinned_version": result.installed,
            "pinned_at": ts,
        }
    _save_raw(data, path)


def load(path: pathlib.Path = _DEFAULT_PATH) -> dict[str, str]:
    """Return {package: pinned_version} mapping."""
    raw = _load_raw(path)
    return {pkg: info["pinned_version"] for pkg, info in raw.items()}


def is_drifted(
    package: str,
    installed: str,
    path: pathlib.Path = _DEFAULT_PATH,
) -> Optional[str]:
    """Return pinned version if installed differs from pin, else None."""
    pins = load(path)
    pinned = pins.get(package)
    if pinned is None:
        return None
    return pinned if pinned != installed else None


def drift_report(
    report: ScanReport, path: pathlib.Path = _DEFAULT_PATH
) -> list[dict]:
    """Return list of {package, installed, pinned} for drifted packages."""
    drifts = []
    for result in report.results:
        pinned = is_drifted(result.package, result.installed, path)
        if pinned is not None:
            drifts.append(
                {
                    "package": result.package,
                    "installed": result.installed,
                    "pinned": pinned,
                }
            )
    return drifts
