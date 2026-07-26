"""Baseline support — gate on *new* auto-execution points only.

Write a baseline once (the auto-run points you've already reviewed and accept),
commit it, then in CI compare against it: only findings whose fingerprint is not
in the baseline are reported / fail the build. This is the open, backend-free
version of "tell me when someone introduces a new auto-run point this week".
"""
from __future__ import annotations

import json
from pathlib import Path

from .models import Finding
from .scanner import ScanResult

BASELINE_VERSION = 1


def write_baseline(result: ScanResult, path: str | Path) -> int:
    """Persist the current findings as the accepted baseline. Returns count."""
    entries = [
        {
            "fingerprint": f.fingerprint,
            "vector_id": f.vector_id,
            "path": f.path,
            "severity": f.effective_severity.label,
        }
        for f in result.findings
    ]
    payload = {"tool": "blastradius", "baseline_version": BASELINE_VERSION, "entries": entries}
    Path(path).write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    return len(entries)


def load_baseline(path: str | Path) -> set[str]:
    """Return the set of accepted fingerprints from a baseline file."""
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    return {e["fingerprint"] for e in data.get("entries", []) if e.get("fingerprint")}


def apply_baseline(findings: list[Finding], accepted: set[str]) -> tuple[list[Finding], int]:
    """Drop findings already in the baseline. Returns (new_findings, suppressed_count)."""
    new = [f for f in findings if f.fingerprint not in accepted]
    return new, len(findings) - len(new)
