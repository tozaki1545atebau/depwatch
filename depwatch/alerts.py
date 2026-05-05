"""Alert dispatchers for depwatch notifications."""

from __future__ import annotations

import logging
import smtplib
from email.message import EmailMessage
from typing import List

from depwatch.checker import CheckResult
from depwatch.config import AlertConfig

logger = logging.getLogger(__name__)


def _format_report(results: List[CheckResult]) -> str:
    """Build a human-readable summary of outdated / vulnerable packages."""
    lines = ["depwatch report", "=" * 40]
    for r in results:
        if r.latest_version and r.latest_version != r.current_version:
            lines.append(
                f"[OUTDATED] {r.package}: {r.current_version} -> {r.latest_version}"
            )
        if r.cves:
            for cve in r.cves:
                lines.append(f"[CVE]      {r.package}: {cve}")
    if len(lines) == 2:
        lines.append("All packages are up-to-date and no CVEs found.")
    return "\n".join(lines)


def send_email_alert(results: List[CheckResult], config: AlertConfig) -> bool:
    """Send an e-mail alert via SMTP.

    Returns True on success, False on failure.
    """
    if not config.email_to or not config.smtp_host:
        logger.warning("Email alert requested but smtp_host / email_to not configured.")
        return False

    body = _format_report(results)
    msg = EmailMessage()
    msg["Subject"] = config.email_subject
    msg["From"] = config.email_from
    msg["To"] = config.email_to
    msg.set_content(body)

    try:
        with smtplib.SMTP(config.smtp_host, config.smtp_port, timeout=10) as smtp:
            if config.smtp_tls:
                smtp.starttls()
            if config.smtp_user and config.smtp_password:
                smtp.login(config.smtp_user, config.smtp_password)
            smtp.send_message(msg)
        logger.info("Email alert sent to %s", config.email_to)
        return True
    except (smtplib.SMTPException, OSError) as exc:
        logger.error("Failed to send email alert: %s", exc)
        return False


def log_alert(results: List[CheckResult], _config: AlertConfig | None = None) -> bool:
    """Write the report to the Python logger (always available fallback)."""
    report = _format_report(results)
    logger.warning(report)
    return True


def dispatch(results: List[CheckResult], config: AlertConfig) -> None:
    """Dispatch alerts according to the configured channels."""
    actionable = [r for r in results if
                  (r.latest_version and r.latest_version != r.current_version) or r.cves]
    if not actionable:
        logger.debug("Nothing to alert on.")
        return

    if config.channel == "email":
        send_email_alert(actionable, config)
    else:
        log_alert(actionable, config)
