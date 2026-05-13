"""Integration tests: pin + drift_report + pin_reporter."""
from __future__ import annotations

import json
import pathlib

import pytest

from depwatch.checker import CheckResult
from depwatch.scanner import ScanReport
from depwatch.pin import drift_report, pin
from depwatch.pin_reporter import render


def _result(pkg: str, installed: str) -> CheckResult:
    return CheckResult(package=pkg, installed=installed, latest=None, cve_result=None)


def _report(*pairs) -> ScanReport:
    return ScanReport(results=[_result(p, v) for p, v in pairs])


@pytest.fixture()
def pin_file(tmp_path: pathlib.Path) -> pathlib.Path:
    return tmp_path / "pins.json"


def test_no_drift_after_immediate_rescan(pin_file):
    report = _report(("requests", "2.31.0"), ("flask", "3.0.0"))
    pin(report, pin_file)
    drifts = drift_report(report, pin_file)
    assert drifts == []


def test_drift_detected_after_upgrade(pin_file):
    original = _report(("requests", "2.28.0"))
    pin(original, pin_file)
    upgraded = _report(("requests", "2.31.0"))
    drifts = drift_report(upgraded, pin_file)
    assert len(drifts) == 1
    assert drifts[0]["pinned"] == "2.28.0"


def test_text_report_shows_drift(pin_file):
    pin(_report(("requests", "2.28.0")), pin_file)
    drifts = drift_report(_report(("requests", "2.31.0")), pin_file)
    output = render(drifts, fmt="text")
    assert "requests" in output
    assert "2.28.0" in output
    assert "2.31.0" in output


def test_json_report_shows_drift(pin_file):
    pin(_report(("flask", "2.3.3")), pin_file)
    drifts = drift_report(_report(("flask", "3.0.0")), pin_file)
    data = json.loads(render(drifts, fmt="json"))
    assert data["count"] == 1
    assert data["drifts"][0]["package"] == "flask"


def test_re_pin_clears_drift(pin_file):
    pin(_report(("requests", "2.28.0")), pin_file)
    upgraded = _report(("requests", "2.31.0"))
    pin(upgraded, pin_file)
    drifts = drift_report(upgraded, pin_file)
    assert drifts == []
