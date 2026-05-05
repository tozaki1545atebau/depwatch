"""High-level scanner that combines version checking and CVE detection."""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Dict, List

from depwatch.checker import CheckResult, check_packages
from depwatch.cve import CVEResult, check_cves
from depwatch.config import DepwatchConfig

logger = logging.getLogger(__name__)


@dataclass
class ScanReport:
    check_results: List[CheckResult] = field(default_factory=list)
    cve_results: List[CVEResult] = field(default_factory=list)

    @property
    def outdated(self) -> List[CheckResult]:
        from depwatch.checker import PackageStatus
        return [r for r in self.check_results if r.status == PackageStatus.OUTDATED]

    @property
    def vulnerable(self) -> List[CVEResult]:
        return [r for r in self.cve_results if r.is_vulnerable]

    @property
    def has_issues(self) -> bool:
        return bool(self.outdated or self.vulnerable)

    def summary(self) -> str:
        lines = [
            f"Packages checked : {len(self.check_results)}",
            f"Outdated         : {len(self.outdated)}",
            f"Vulnerable       : {len(self.vulnerable)}",
        ]
        return "\n".join(lines)


def _installed_versions(check_results: List[CheckResult]) -> Dict[str, str]:
    """Extract {name: installed_version} from check results."""
    return {
        r.package: r.installed_version
        for r in check_results
        if r.installed_version is not None
    }


def run_scan(config: DepwatchConfig) -> ScanReport:
    """Run a full dependency scan: version check + CVE lookup."""
    logger.info("Starting dependency scan for %d package(s).", len(config.packages))

    check_results = check_packages(config.packages)
    logger.info("Version check complete.")

    installed = _installed_versions(check_results)
    cve_results = check_cves(installed) if config.check_cves else []
    if config.check_cves:
        logger.info("CVE check complete.")
    else:
        logger.info("CVE checking disabled; skipping.")

    report = ScanReport(check_results=check_results, cve_results=cve_results)
    logger.info("Scan finished. Issues found: %s", report.has_issues)
    return report
