"""Diff two ScanReports to surface what changed between runs."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Sequence

from depwatch.checker import CheckResult, PackageStatus
from depwatch.scanner import ScanReport


@dataclass
class PackageDiff:
    package_name: str
    previous_version: str | None
    current_version: str | None
    previous_status: PackageStatus | None
    current_status: PackageStatus | None
    new_cves: list[str] = field(default_factory=list)
    resolved_cves: list[str] = field(default_factory=list)

    @property
    def has_changes(self) -> bool:
        return (
            self.previous_version != self.current_version
            or self.previous_status != self.current_status
            or bool(self.new_cves)
            or bool(self.resolved_cves)
        )


@dataclass
class ScanDiff:
    added: list[str] = field(default_factory=list)
    removed: list[str] = field(default_factory=list)
    changed: list[PackageDiff] = field(default_factory=list)

    @property
    def is_empty(self) -> bool:
        return not (self.added or self.removed or self.changed)


def _cve_ids(result: CheckResult) -> set[str]:
    if result.cve_result is None:
        return set()
    return {v.cve_id for v in result.cve_result.vulnerabilities}


def compute(previous: ScanReport, current: ScanReport) -> ScanDiff:
    """Return a :class:`ScanDiff` describing changes from *previous* to *current*."""
    prev_map = {r.package_name: r for r in previous.results}
    curr_map = {r.package_name: r for r in current.results}

    added = [name for name in curr_map if name not in prev_map]
    removed = [name for name in prev_map if name not in curr_map]

    changed: list[PackageDiff] = []
    for name in set(prev_map) & set(curr_map):
        p, c = prev_map[name], curr_map[name]
        prev_cves = _cve_ids(p)
        curr_cves = _cve_ids(c)
        diff = PackageDiff(
            package_name=name,
            previous_version=p.installed_version,
            current_version=c.installed_version,
            previous_status=p.status,
            current_status=c.status,
            new_cves=sorted(curr_cves - prev_cves),
            resolved_cves=sorted(prev_cves - curr_cves),
        )
        if diff.has_changes:
            changed.append(diff)

    return ScanDiff(added=sorted(added), removed=sorted(removed), changed=changed)
