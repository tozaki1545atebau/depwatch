"""Policy engine: evaluate scan reports against user-defined rules."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Optional

from depwatch.scanner import ScanReport
from depwatch.severity_filter import _severity_rank


@dataclass
class PolicyRule:
    """A single policy rule."""
    name: str
    max_outdated: Optional[int] = None          # fail if outdated count exceeds this
    max_vulnerabilities: Optional[int] = None   # fail if vuln count exceeds this
    min_severity: Optional[str] = None          # fail if any vuln >= this severity
    blocked_packages: List[str] = field(default_factory=list)  # packages that must not appear


@dataclass
class PolicyViolation:
    rule_name: str
    message: str


@dataclass
class PolicyResult:
    violations: List[PolicyViolation] = field(default_factory=list)

    @property
    def passed(self) -> bool:
        return len(self.violations) == 0

    def summary(self) -> str:
        if self.passed:
            return "Policy check passed."
        lines = [f"Policy check FAILED ({len(self.violations)} violation(s)):"]
        for v in self.violations:
            lines.append(f"  [{v.rule_name}] {v.message}")
        return "\n".join(lines)


def evaluate(report: ScanReport, rules: List[PolicyRule]) -> PolicyResult:
    """Evaluate *report* against every rule and return a PolicyResult."""
    result = PolicyResult()

    for rule in rules:
        outdated_count = len(report.outdated)
        vuln_count = len(report.vulnerable)

        if rule.max_outdated is not None and outdated_count > rule.max_outdated:
            result.violations.append(PolicyViolation(
                rule_name=rule.name,
                message=(
                    f"Outdated packages ({outdated_count}) exceed "
                    f"allowed maximum ({rule.max_outdated})."
                ),
            ))

        if rule.max_vulnerabilities is not None and vuln_count > rule.max_vulnerabilities:
            result.violations.append(PolicyViolation(
                rule_name=rule.name,
                message=(
                    f"Vulnerable packages ({vuln_count}) exceed "
                    f"allowed maximum ({rule.max_vulnerabilities})."
                ),
            ))

        if rule.min_severity is not None:
            threshold = _severity_rank(rule.min_severity)
            for pkg_result in report.vulnerable:
                for vuln in pkg_result.cve_result.vulnerabilities:
                    if _severity_rank(vuln.severity) >= threshold:
                        result.violations.append(PolicyViolation(
                            rule_name=rule.name,
                            message=(
                                f"Package '{pkg_result.package}' has "
                                f"{vuln.severity.upper()} vulnerability {vuln.cve_id} "
                                f"(threshold: {rule.min_severity.upper()})."
                            ),
                        ))

        blocked = {p.lower() for p in rule.blocked_packages}
        for pkg_result in report.results:
            if pkg_result.package.lower() in blocked:
                result.violations.append(PolicyViolation(
                    rule_name=rule.name,
                    message=f"Blocked package '{pkg_result.package}' is present.",
                ))

    return result
