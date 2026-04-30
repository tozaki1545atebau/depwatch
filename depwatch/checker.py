"""Checks installed packages for outdated versions using PyPI JSON API."""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Optional

import httpx

logger = logging.getLogger(__name__)

PYPI_URL = "https://pypi.org/pypi/{package}/json"


@dataclass
class PackageStatus:
    name: str
    installed_version: str
    latest_version: str
    is_outdated: bool
    error: Optional[str] = None


@dataclass
class CheckResult:
    outdated: list[PackageStatus] = field(default_factory=list)
    up_to_date: list[PackageStatus] = field(default_factory=list)
    errors: list[PackageStatus] = field(default_factory=list)

    @property
    def total(self) -> int:
        return len(self.outdated) + len(self.up_to_date) + len(self.errors)


def fetch_latest_version(package: str, client: httpx.Client) -> Optional[str]:
    """Return the latest version string from PyPI, or None on failure."""
    try:
        response = client.get(PYPI_URL.format(package=package), timeout=10)
        response.raise_for_status()
        return response.json()["info"]["version"]
    except httpx.HTTPStatusError as exc:
        logger.warning("PyPI returned %s for %s", exc.response.status_code, package)
    except (httpx.RequestError, KeyError, ValueError) as exc:
        logger.warning("Failed to fetch %s from PyPI: %s", package, exc)
    return None


def check_packages(packages: dict[str, str]) -> CheckResult:
    """Check a mapping of {package_name: installed_version} against PyPI.

    Returns a CheckResult with categorised PackageStatus entries.
    """
    result = CheckResult()

    with httpx.Client() as client:
        for name, installed in packages.items():
            latest = fetch_latest_version(name, client)
            if latest is None:
                result.errors.append(
                    PackageStatus(
                        name=name,
                        installed_version=installed,
                        latest_version="unknown",
                        is_outdated=False,
                        error="Could not retrieve version from PyPI",
                    )
                )
                continue

            is_outdated = installed != latest
            status = PackageStatus(
                name=name,
                installed_version=installed,
                latest_version=latest,
                is_outdated=is_outdated,
            )
            if is_outdated:
                result.outdated.append(status)
                logger.info("%s is outdated (%s -> %s)", name, installed, latest)
            else:
                result.up_to_date.append(status)

    return result
