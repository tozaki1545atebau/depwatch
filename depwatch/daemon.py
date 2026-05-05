"""Entry-point that wires config, scanner, alerts, and scheduler together."""

import logging
from pathlib import Path
from typing import Optional

from depwatch.alerts import dispatch
from depwatch.config import DepwatchConfig, from_env, from_file
from depwatch.scanner import ScanReport, scan
from depwatch.scheduler import Scheduler

logger = logging.getLogger(__name__)


def _build_config(config_path: Optional[str]) -> DepwatchConfig:
    if config_path and Path(config_path).exists():
        logger.info("Loading config from %s", config_path)
        return from_file(config_path)
    logger.info("Loading config from environment variables")
    return from_env()


def _make_scan_callback(cfg: DepwatchConfig) -> None:
    """Return a zero-argument callable that runs one full scan+alert cycle."""

    def _callback() -> None:
        logger.info("Starting dependency scan for %d package(s)", len(cfg.packages))
        report: ScanReport = scan(cfg)
        logger.info("Scan complete — %s", report.summary())
        if report.has_issues():
            dispatch(report, cfg.alert)
        else:
            logger.info("No issues found; skipping alert dispatch")

    return _callback


def run(config_path: Optional[str] = None) -> None:
    """Bootstrap and run the depwatch daemon."""
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)-8s %(name)s — %(message)s",
    )
    cfg = _build_config(config_path)
    callback = _make_scan_callback(cfg)
    scheduler = Scheduler(
        interval_seconds=cfg.interval_seconds,
        callback=callback,
    )
    scheduler.start()


if __name__ == "__main__":
    run()
