"""Generates human-readable and machine-readable reports from scan results."""
from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Literal

from depwatch.scanner import ScanReport

OutputFormat = Literal["text", "json"]


def _utcnow() -> str:
    return datetime.now(tz=timezone.utc).isoformat(timespec="seconds")


def render_text(report: ScanReport) -> str:
    """Return a plain-text summary of the scan report."""
    lines: list[str] = [
        f"depwatch scan — {_utcnow()}",
        f"Packages checked : {len(report.results)}",
        f"Outdated         : {len(report.outdated)}",
        f"Vulnerable       : {len(report.vulnerable)}",
        "",
    ]

    if report.outdated:
        lines.append("Outdated packages:")
        for r in report.outdated:
            lines.append(
                f"  {r.package:<30} {r.current_version!s:<15} -> {r.latest_version}"
            )
        lines.append("")

    if report.vulnerable:
        lines.append("Vulnerable packages:")
        for r in report.vulnerable:
            ids = ", ".join(v.cve_id for v in r.vulnerabilities)
            lines.append(f"  {r.package:<30} CVEs: {ids}")
        lines.append("")

    if not report.has_issues:
        lines.append("All packages are up-to-date and vulnerability-free.")

    return "\n".join(lines)


def render_json(report: ScanReport) -> str:
    """Return a JSON-serialisable representation of the scan report."""
    data = {
        "generated_at": _utcnow(),
        "summary": {
            "total": len(report.results),
            "outdated": len(report.outdated),
            "vulnerable": len(report.vulnerable),
        },
        "packages": [
            {
                "name": r.package,
                "current_version": r.current_version,
                "latest_version": r.latest_version,
                "is_outdated": r.is_outdated,
                "vulnerabilities": [
                    {
                        "cve_id": v.cve_id,
                        "severity": v.severity,
                        "description": v.description,
                    }
                    for v in r.vulnerabilities
                ],
            }
            for r in report.results
        ],
    }
    return json.dumps(data, indent=2)


def render(report: ScanReport, fmt: OutputFormat = "text") -> str:
    """Dispatch to the appropriate renderer."""
    if fmt == "json":
        return render_json(report)
    return render_text(report)
