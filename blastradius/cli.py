"""BlastRadius command-line interface."""
from __future__ import annotations

import argparse
import sys

from .models import Severity
from .report import render_json, render_sarif, render_terminal
from .scanner import scan

_LEVELS = ["info", "low", "medium", "high", "critical"]


def _sev(name: str) -> Severity:
    return Severity.from_hint(name)


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="blastradius",
        description="Find every place an AI agent — or the repo itself — can run code "
                    "without your explicit approval.",
    )
    p.add_argument("path", nargs="?", default=".", help="directory to scan (default: .)")
    p.add_argument("-f", "--format", choices=["terminal", "json", "sarif"],
                   default="terminal", help="output format")
    p.add_argument("--min-severity", choices=_LEVELS, default="low",
                   help="hide findings below this severity (default: low)")
    p.add_argument("--fail-on", choices=_LEVELS + ["never"], default="high",
                   help="exit non-zero if any finding at/above this severity (default: high)")
    p.add_argument("--exclude", action="append", default=[], metavar="GLOB",
                   help="path prefix or glob to skip (repeatable), e.g. --exclude fixtures")
    p.add_argument("--no-color", action="store_true", help="disable ANSI colour")
    p.add_argument("-q", "--quiet", action="store_true",
                   help="suppress the report, only set exit code (useful with --fail-on)")
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        result = scan(args.path, excludes=args.exclude)
    except FileNotFoundError as e:
        print(f"blastradius: {e}", file=sys.stderr)
        return 2

    min_sev = _sev(args.min_severity)
    result.findings = [f for f in result.findings if f.effective_severity >= min_sev]

    if not args.quiet:
        use_color = (not args.no_color) and sys.stdout.isatty() and args.format == "terminal"
        if args.format == "json":
            render_json(result, sys.stdout)
        elif args.format == "sarif":
            render_sarif(result, sys.stdout)
        else:
            render_terminal(result, sys.stdout, use_color=use_color)

    if args.fail_on == "never":
        return 0
    threshold = _sev(args.fail_on)
    return 1 if result.count_at_or_above(threshold) else 0


if __name__ == "__main__":
    raise SystemExit(main())
