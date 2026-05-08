"""Generates remediation hints for outdated packages and CVEs."""
from __future__ import annotations

from dataclasses import dataclass
from typing import List, Optional

from depwatch.scanner import ScanReport
from depwatch.checker import CheckResult
from depwatch.cve import Vulnerability


@dataclass
class PackageRemediation:
    package: str
    current_version: Optional[str]
    latest_version: Optional[str]
    cve_ids: List[str]
    upgrade_command: str
    notes: str

    def as_dict(self) -> dict:
        return {
            "package": self.package,
            "current_version": self.current_version,
            "latest_version": self.latest_version,
            "cve_ids": self.cve_ids,
            "upgrade_command": self.upgrade_command,
            "notes": self.notes,
        }


def _upgrade_command(package: str, latest: Optional[str]) -> str:
    if latest:
        return f"pip install --upgrade {package}=={latest}"
    return f"pip install --upgrade {package}"


def _notes(result: CheckResult) -> str:
    parts: List[str] = []
    if result.cve_result and result.cve_result.vulnerabilities:
        severities = {
            v.severity.upper()
            for v in result.cve_result.vulnerabilities
            if v.severity
        }
        if "CRITICAL" in severities:
            parts.append("Contains CRITICAL vulnerabilities — upgrade immediately.")
        elif "HIGH" in severities:
            parts.append("Contains HIGH severity vulnerabilities — prioritise upgrade.")
    if result.latest_version and result.current_version:
        if result.latest_version != result.current_version:
            parts.append(
                f"Upgrade from {result.current_version} to {result.latest_version}."
            )
    return " ".join(parts) if parts else "Review and upgrade as appropriate."


def build_remediation(report: ScanReport) -> List[PackageRemediation]:
    """Return a remediation entry for every package that has issues."""
    items: List[PackageRemediation] = []
    for result in report.results:
        is_outdated = (
            result.latest_version is not None
            and result.latest_version != result.current_version
        )
        cve_ids = [
            v.cve_id
            for v in (result.cve_result.vulnerabilities if result.cve_result else [])
        ]
        if not is_outdated and not cve_ids:
            continue
        items.append(
            PackageRemediation(
                package=result.package,
                current_version=result.current_version,
                latest_version=result.latest_version,
                cve_ids=cve_ids,
                upgrade_command=_upgrade_command(result.package, result.latest_version),
                notes=_notes(result),
            )
        )
    return items
