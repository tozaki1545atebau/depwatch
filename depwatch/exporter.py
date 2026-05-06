"""Export scan reports to various file formats (JSON, CSV)."""

from __future__ import annotations

import csv
import io
import json
from datetime import datetime, timezone
from typing import Any

from depwatch.scanner import ScanReport


def _utcnow() -> str:
    return datetime.now(timezone.utc).isoformat()


def _report_to_dict(report: ScanReport, timestamp: str | None = None) -> dict[str, Any]:
    ts = timestamp or _utcnow()
    packages = []
    for result in report.results:
        entry: dict[str, Any] = {
            "package": result.package,
            "current_version": result.current_version,
            "latest_version": result.latest_version,
            "is_outdated": result.is_outdated,
            "vulnerabilities": [
                {
                    "id": v.vuln_id,
                    "summary": v.summary,
                    "severity": v.severity,
                }
                for v in result.vulnerabilities
            ],
        }
        packages.append(entry)
    return {"generated_at": ts, "packages": packages}


def export_json(report: ScanReport, timestamp: str | None = None) -> str:
    """Serialize a ScanReport to a JSON string."""
    data = _report_to_dict(report, timestamp)
    return json.dumps(data, indent=2)


def export_csv(report: ScanReport) -> str:
    """Serialize a ScanReport to CSV text.

    Each row represents one package.  Vulnerability IDs are joined with '|'.
    """
    output = io.StringIO()
    fieldnames = [
        "package",
        "current_version",
        "latest_version",
        "is_outdated",
        "vulnerability_ids",
        "severities",
    ]
    writer = csv.DictWriter(output, fieldnames=fieldnames)
    writer.writeheader()
    for result in report.results:
        vuln_ids = "|".join(v.vuln_id for v in result.vulnerabilities)
        severities = "|".join(v.severity for v in result.vulnerabilities)
        writer.writerow(
            {
                "package": result.package,
                "current_version": result.current_version,
                "latest_version": result.latest_version,
                "is_outdated": result.is_outdated,
                "vulnerability_ids": vuln_ids,
                "severities": severities,
            }
        )
    return output.getvalue()


def export(report: ScanReport, fmt: str, timestamp: str | None = None) -> str:
    """Dispatch to the correct exporter.  *fmt* is 'json' or 'csv'."""
    if fmt == "json":
        return export_json(report, timestamp)
    if fmt == "csv":
        return export_csv(report)
    raise ValueError(f"Unsupported export format: {fmt!r}")
