"""Filter scan results by CVE severity level."""

from __future__ import annotations

from typing import List

from depwatch.cve import Vulnerability
from depwatch.scanner import ScanReport
from depwatch.checker import CheckResult

# Ordered from least to most severe
_SEVERITY_ORDER = ["unknown", "low", "medium", "high", "critical"]


def _severity_rank(severity: str) -> int:
    """Return a numeric rank for a severity string (case-insensitive)."""
    return _SEVERITY_ORDER.index(severity.lower()) if severity.lower() in _SEVERITY_ORDER else 0


def filter_vulnerabilities(vulns: List[Vulnerability], min_severity: str) -> List[Vulnerability]:
    """Return only vulnerabilities at or above *min_severity*."""
    threshold = _severity_rank(min_severity)
    return [v for v in vulns if _severity_rank(v.severity) >= threshold]


def filter_report(report: ScanReport, min_severity: str) -> ScanReport:
    """Return a new ScanReport with CVEs below *min_severity* stripped out.

    Packages whose entire CVE list is filtered out retain their version
    information but appear with an empty vulnerability list, so they no
    longer count as vulnerable.
    """
    filtered_results: List[CheckResult] = []
    for result in report.results:
        kept_vulns = filter_vulnerabilities(result.cve_result.vulnerabilities, min_severity)
        if kept_vulns == result.cve_result.vulnerabilities:
            # Nothing changed — reuse the original object unchanged.
            filtered_results.append(result)
        else:
            from depwatch.cve import CVEResult
            new_cve = CVEResult(
                package=result.cve_result.package,
                version=result.cve_result.version,
                vulnerabilities=kept_vulns,
            )
            from depwatch.checker import CheckResult as CR
            filtered_results.append(
                CR(
                    package=result.package,
                    current_version=result.current_version,
                    latest_version=result.latest_version,
                    cve_result=new_cve,
                )
            )
    return ScanReport(results=filtered_results)
