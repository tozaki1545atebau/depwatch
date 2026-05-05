"""Minimal CLI entry-point for depwatch.

Usage:
    python -m depwatch.cli [--format text|json] [--config PATH]
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

from depwatch.config import from_env, from_file
from depwatch.reporter import OutputFormat, render
from depwatch.scanner import ScanReport


def _build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="depwatch",
        description="Check Python dependencies for outdated versions and CVEs.",
    )
    parser.add_argument(
        "--format",
        choices=["text", "json"],
        default="text",
        dest="fmt",
        help="Output format (default: text)",
    )
    parser.add_argument(
        "--config",
        metavar="PATH",
        default=None,
        help="Path to depwatch.toml (falls back to env vars if omitted)",
    )
    parser.add_argument(
        "--requirements",
        metavar="PATH",
        default=None,
        help="Override requirements file path from config",
    )
    return parser


def _load_config(config_path: str | None):
    if config_path is not None:
        return from_file(Path(config_path))
    try:
        return from_file(Path("depwatch.toml"))
    except FileNotFoundError:
        return from_env()


def main(argv: list[str] | None = None) -> int:
    parser = _build_arg_parser()
    args = parser.parse_args(argv)

    try:
        config = _load_config(args.config)
    except Exception as exc:  # noqa: BLE001
        print(f"[depwatch] configuration error: {exc}", file=sys.stderr)
        return 2

    if args.requirements:
        config = config._replace(requirements_file=args.requirements)

    try:
        from depwatch.daemon import _make_scan_callback  # local import to keep CLI fast

        report: ScanReport = _make_scan_callback(config)()
    except Exception as exc:  # noqa: BLE001
        print(f"[depwatch] scan error: {exc}", file=sys.stderr)
        return 1

    print(render(report, fmt=args.fmt))
    return 0


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
