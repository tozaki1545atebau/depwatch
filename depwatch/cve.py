"""CVE vulnerability checking via OSV.dev API."""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import List, Optional

import requests

OSV_API_URL = "https://api.osv.dev/v1/query"
REQUEST_TIMEOUT = 10

logger = logging.getLogger(__name__)


@dataclass
class Vulnerability:
    vuln_id: str
    summary: str
    severity: Optional[str] = None
    aliases: List[str] = field(default_factory=list)

    def __str__(self) -> str:
        sev = f" [{self.severity}]" if self.severity else ""
        return f"{self.vuln_id}{sev}: {self.summary}"


@dataclass
class CVEResult:
    package: str
    version: str
    vulnerabilities: List[Vulnerability] = field(default_factory=list)

    @property
    def is_vulnerable(self) -> bool:
        return len(self.vulnerabilities) > 0


def _parse_severity(vuln: dict) -> Optional[str]:
    severities = vuln.get("severity", [])
    if severities:
        return severities[0].get("score")
    database_specific = vuln.get("database_specific", {})
    return database_specific.get("severity")


def fetch_vulnerabilities(package: str, version: str) -> CVEResult:
    """Query OSV.dev for known vulnerabilities for a package version."""
    payload = {
        "version": version,
        "package": {"name": package, "ecosystem": "PyPI"},
    }
    result = CVEResult(package=package, version=version)
    try:
        resp = requests.post(OSV_API_URL, json=payload, timeout=REQUEST_TIMEOUT)
        resp.raise_for_status()
        data = resp.json()
        for vuln in data.get("vulns", []):
            result.vulnerabilities.append(
                Vulnerability(
                    vuln_id=vuln.get("id", "UNKNOWN"),
                    summary=vuln.get("summary", "No summary available."),
                    severity=_parse_severity(vuln),
                    aliases=vuln.get("aliases", []),
                )
            )
    except requests.HTTPError as exc:
        logger.warning("HTTP error querying OSV for %s==%s: %s", package, version, exc)
    except requests.RequestException as exc:
        logger.warning("Request error querying OSV for %s==%s: %s", package, version, exc)
    return result


def check_cves(packages: dict[str, str]) -> List[CVEResult]:
    """Check a dict of {package: installed_version} for CVEs."""
    results = []
    for pkg, ver in packages.items():
        cve_result = fetch_vulnerabilities(pkg, ver)
        results.append(cve_result)
        if cve_result.is_vulnerable:
            logger.info("%s==%s has %d known vulnerability/ies", pkg, ver, len(cve_result.vulnerabilities))
    return results
