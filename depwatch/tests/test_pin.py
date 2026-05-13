"""Tests for depwatch.pin."""
from __future__ import annotations

import json
import pathlib

import pytest

from depwatch.checker import CheckResult
from depwatch.scanner import ScanReport
from depwatch.pin import drift_report, is_drifted, load, pin


def _result(pkg: str, installed: str) -> CheckResult:
    return CheckResult(package=pkg, installed=installed, latest=None, cve_result=None)


@pytest.fixture()
def pin_file(tmp_path: pathlib.Path) -> pathlib.Path:
    return tmp_path / "pins.json"


def _report(*pairs) -> ScanReport:
    results = [_result(p, v) for p, v in pairs]
    return ScanReport(results=results)


def test_pin_creates_file(pin_file):
    report = _report(("requests", "2.31.0"))
    pin(report, pin_file)
    assert pin_file.exists()


def test_pin_stores_version(pin_file):
    report = _report(("requests", "2.31.0"))
    pin(report, pin_file)
    pins = load(pin_file)
    assert pins["requests"] == "2.31.0"


def test_pin_multiple_packages(pin_file):
    report = _report(("requests", "2.31.0"), ("flask", "3.0.0"))
    pin(report, pin_file)
    pins = load(pin_file)
    assert pins["requests"] == "2.31.0"
    assert pins["flask"] == "3.0.0"


def test_pin_overwrites_existing(pin_file):
    pin(_report(("requests", "2.28.0")), pin_file)
    pin(_report(("requests", "2.31.0")), pin_file)
    pins = load(pin_file)
    assert pins["requests"] == "2.31.0"


def test_load_returns_empty_when_no_file(tmp_path):
    result = load(tmp_path / "nonexistent.json")
    assert result == {}


def test_is_drifted_returns_none_when_matches(pin_file):
    pin(_report(("requests", "2.31.0")), pin_file)
    assert is_drifted("requests", "2.31.0", pin_file) is None


def test_is_drifted_returns_pinned_when_differs(pin_file):
    pin(_report(("requests", "2.28.0")), pin_file)
    result = is_drifted("requests", "2.31.0", pin_file)
    assert result == "2.28.0"


def test_is_drifted_returns_none_for_unknown_package(pin_file):
    pin(_report(("flask", "3.0.0")), pin_file)
    assert is_drifted("requests", "2.31.0", pin_file) is None


def test_drift_report_empty_when_no_drift(pin_file):
    report = _report(("requests", "2.31.0"))
    pin(report, pin_file)
    drifts = drift_report(report, pin_file)
    assert drifts == []


def test_drift_report_detects_changed_version(pin_file):
    pin(_report(("requests", "2.28.0")), pin_file)
    new_report = _report(("requests", "2.31.0"))
    drifts = drift_report(new_report, pin_file)
    assert len(drifts) == 1
    assert drifts[0]["package"] == "requests"
    assert drifts[0]["installed"] == "2.31.0"
    assert drifts[0]["pinned"] == "2.28.0"
