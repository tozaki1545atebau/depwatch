"""Periodic scan scheduler for depwatch daemon."""

import logging
import signal
import time
from typing import Callable, Optional

logger = logging.getLogger(__name__)


class Scheduler:
    """Runs a scan callback on a fixed interval until stopped."""

    def __init__(self, interval_seconds: int, callback: Callable[[], None]) -> None:
        if interval_seconds <= 0:
            raise ValueError("interval_seconds must be a positive integer")
        self.interval = interval_seconds
        self.callback = callback
        self._running = False
        self._tick_count = 0

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def start(self) -> None:
        """Block and run the callback on every interval until stopped."""
        self._running = True
        self._register_signals()
        logger.info("Scheduler started (interval=%ds)", self.interval)
        try:
            while self._running:
                self._run_once()
                self._sleep(self.interval)
        except KeyboardInterrupt:
            pass
        finally:
            logger.info("Scheduler stopped after %d tick(s)", self._tick_count)

    def stop(self) -> None:
        """Signal the run-loop to exit after the current sleep."""
        self._running = False

    @property
    def tick_count(self) -> int:
        return self._tick_count

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _run_once(self) -> None:
        self._tick_count += 1
        logger.debug("Tick #%d — running scan callback", self._tick_count)
        try:
            self.callback()
        except Exception as exc:  # noqa: BLE001
            logger.error("Scan callback raised an exception: %s", exc)

    def _sleep(self, seconds: int) -> None:
        """Interruptible sleep: checks _running every second."""
        for _ in range(seconds):
            if not self._running:
                break
            time.sleep(1)

    def _register_signals(self) -> None:
        signal.signal(signal.SIGTERM, self._handle_signal)
        signal.signal(signal.SIGINT, self._handle_signal)

    def _handle_signal(self, signum: int, frame: Optional[object]) -> None:  # noqa: ARG002
        logger.info("Received signal %d — stopping scheduler", signum)
        self.stop()
