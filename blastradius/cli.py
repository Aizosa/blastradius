"""BlastRadius command-line interface."""
from __future__ import annotations

import argparse
import sys

from . import baseline as _baseline
from . import policy as _policy
from .models import Severity
from .report import (
    render_html, render_json, render_markdown, render_sarif, render_terminal,
)
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
    p.add_argument("-f", "--format", choices=["terminal", "json", "sarif", "markdown", "html"],
                   default="terminal", help="output format")
    p.add_argument("--min-severity", choices=_LEVELS, default=None,
                   help="hide findings below this severity (default: low, or config)")
    p.add_argument("--fail-on", choices=_LEVELS + ["never"], default=None,
                   help="exit non-zero if any finding at/above this severity (default: high, or config)")
    p.add_argument("--exclude", action="append", default=[], metavar="GLOB",
                   help="path prefix or glob to skip (repeatable), e.g. --exclude fixtures")
    p.add_argument("--include-home", action="store_true",
                   help="also scan user-level config (~/.gitconfig, ~/.claude, ~/.npmrc, ~/.ssh/config, …)")
    p.add_argument("--config", metavar="FILE",
                   help="policy config (default: auto-detect .blastradius.json in scan path)")
    p.add_argument("--no-config", action="store_true", help="ignore any .blastradius.json")
    p.add_argument("--baseline", metavar="FILE",
                   help="suppress findings recorded in this baseline (report only NEW ones)")
    p.add_argument("--write-baseline", metavar="FILE",
                   help="write current findings as an accepted baseline, then exit")
    p.add_argument("--no-color", action="store_true", help="disable ANSI colour")
    p.add_argument("-q", "--quiet", action="store_true",
                   help="suppress the report, only set exit code (useful with --fail-on)")
    return p


def _resolve(cli_val, cfg_val, default):
    if cli_val is not None:
        return cli_val
    if cfg_val:
        return cfg_val
    return default


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    # 1. policy config
    cfg = _policy.Config()
    if not args.no_config:
        cfg_path = _policy.find_config(args.path, args.config)
        if cfg_path:
            try:
                cfg = _policy.load_config(cfg_path)
            except (ValueError, OSError, TypeError) as e:
                print(f"blastradius: bad config {cfg_path}: {e}", file=sys.stderr)
                return 2
        elif args.config:
            print(f"blastradius: config not found: {args.config}", file=sys.stderr)
            return 2

    custom = _policy.build_custom_detectors(cfg.custom_rules)
    excludes = list(args.exclude) + list(cfg.exclude)

    # 2. scan
    try:
        result = scan(
            args.path,
            excludes=excludes,
            extra_detectors=custom,
            severity_overrides=cfg.overrides_as_severity,
            ignore_vectors=cfg.ignore_vectors,
            ignore_fingerprints=cfg.ignore_fingerprints,
            include_home=args.include_home,
        )
    except FileNotFoundError as e:
        print(f"blastradius: {e}", file=sys.stderr)
        return 2

    # 3. write-baseline short-circuits
    if args.write_baseline:
        try:
            n = _baseline.write_baseline(result, args.write_baseline)
        except OSError as e:
            print(f"blastradius: cannot write baseline {args.write_baseline}: {e}", file=sys.stderr)
            return 2
        print(f"blastradius: wrote baseline with {n} accepted finding(s) to {args.write_baseline}",
              file=sys.stderr)
        return 0

    # 4. baseline diff
    if args.baseline:
        try:
            accepted = _baseline.load_baseline(args.baseline)
        except (OSError, ValueError, TypeError, AttributeError) as e:
            print(f"blastradius: bad baseline {args.baseline}: {e}", file=sys.stderr)
            return 2
        result.findings, suppressed = _baseline.apply_baseline(result.findings, accepted)
        if suppressed and not args.quiet:
            print(f"blastradius: baseline suppressed {suppressed} known finding(s)", file=sys.stderr)

    # findings after baseline — used for the CI gate (min-severity is display-only)
    gate_findings = list(result.findings)

    # 5. min-severity filter (affects the report only, never the exit code)
    min_sev = _sev(_resolve(args.min_severity, cfg.min_severity, "low"))
    result.findings = [f for f in result.findings if f.effective_severity >= min_sev]

    # 6. render
    if not args.quiet:
        use_color = (not args.no_color) and sys.stdout.isatty() and args.format == "terminal"
        renderers = {
            "json": render_json, "sarif": render_sarif,
            "markdown": render_markdown, "html": render_html,
        }
        if args.format == "terminal":
            render_terminal(result, sys.stdout, use_color=use_color)
        else:
            renderers[args.format](result, sys.stdout)

    # 7. exit code — gated on the post-baseline findings, independent of --min-severity
    fail_on = _resolve(args.fail_on, cfg.fail_on, "high")
    if fail_on == "never":
        return 0
    threshold = _sev(fail_on)
    return 1 if any(f.effective_severity >= threshold for f in gate_findings) else 0


if __name__ == "__main__":
    raise SystemExit(main())
