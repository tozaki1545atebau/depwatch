"""Webhook alert dispatcher for depwatch."""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from typing import Optional

import requests

from depwatch.scanner import ScanReport

log = logging.getLogger(__name__)

_DEFAULT_TIMEOUT = 10


@dataclass
class WebhookConfig:
    url: str
    secret: Optional[str] = None
    timeout: int = _DEFAULT_TIMEOUT


def _build_payload(report: ScanReport) -> dict:
    """Serialise a ScanReport into a JSON-safe dict."""
    return {
        "summary": report.summary(),
        "outdated": [
            {"package": r.package, "current": r.current_version, "latest": r.latest_version}
            for r in report.outdated()
        ],
        "vulnerable": [
            {
                "package": r.package,
                "cve_ids": [v.cve_id for v in (r.cve_result.vulnerabilities if r.cve_result else [])],
            }
            for r in report.vulnerable()
        ],
    }


def send(report: ScanReport, cfg: WebhookConfig) -> bool:
    """POST the scan report to the configured webhook URL.

    Returns True on success, False on any error.
    """
    payload = _build_payload(report)
    headers = {"Content-Type": "application/json"}
    if cfg.secret:
        headers["X-Depwatch-Secret"] = cfg.secret

    try:
        resp = requests.post(
            cfg.url,
            data=json.dumps(payload),
            headers=headers,
            timeout=cfg.timeout,
        )
        resp.raise_for_status()
        log.info("Webhook delivered to %s (status %s)", cfg.url, resp.status_code)
        return True
    except requests.RequestException as exc:
        log.error("Webhook delivery failed: %s", exc)
        return False
