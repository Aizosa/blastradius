"""Output renderers: terminal, JSON, SARIF."""
from __future__ import annotations

import json
from typing import TextIO

from .models import Severity
from .scanner import ScanResult

_COLORS = {
    Severity.CRITICAL: "\033[97;41m",  # white on red
    Severity.HIGH: "\033[91m",
    Severity.MEDIUM: "\033[93m",
    Severity.LOW: "\033[96m",
    Severity.INFO: "\033[90m",
}
_RESET = "\033[0m"
_DIM = "\033[90m"
_BOLD = "\033[1m"

_ICON = {
    Severity.CRITICAL: "🔴",
    Severity.HIGH: "🟠",
    Severity.MEDIUM: "🟡",
    Severity.LOW: "🔵",
    Severity.INFO: "⚪",
}


def _c(text: str, color: str, use_color: bool) -> str:
    return f"{color}{text}{_RESET}" if use_color else text


def render_terminal(result: ScanResult, out: TextIO, use_color: bool = True) -> None:
    findings = result.findings
    w = 74
    title = " BlastRadius — auto-execution scan "
    out.write("\n" + _c("╭" + "─" * w + "╮", _DIM, use_color) + "\n")
    out.write(_c("│", _DIM, use_color) + _c(title.center(w), _BOLD, use_color)
              + _c("│", _DIM, use_color) + "\n")
    out.write(_c("╰" + "─" * w + "╯", _DIM, use_color) + "\n")
    out.write(f"{_DIM if use_color else ''}scanned {result.files_scanned} files "
              f"with {result.detectors_run} detectors in {result.root}{_RESET if use_color else ''}\n")

    if not findings:
        out.write("\n" + _c("✓ No auto-execution points found.", "\033[92m", use_color) + "\n\n")
        return

    # blast-radius summary line
    buckets = result.by_severity()
    parts = []
    for sev in (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW):
        n = len(buckets[sev])
        if n:
            parts.append(_c(f"{_ICON[sev]} {n} {sev.label}", _COLORS[sev], use_color))
    out.write("\nBlast radius: " + "   ".join(parts) + "\n")

    for i, f in enumerate(findings, 1):
        sev = f.effective_severity
        bar = _c(f" {sev.label} ", _COLORS[sev], use_color)
        out.write("\n" + _c("─" * (w + 2), _DIM, use_color) + "\n")
        out.write(f"{_ICON[sev]}{bar} {_c(f.title, _BOLD, use_color)}  {_DIM if use_color else ''}[{f.vector_id}]{_RESET if use_color else ''}\n")
        out.write(f"   {_c('file', _DIM, use_color)}     {f.path}"
                  + (f":{f.line}" if f.line else "") + "\n")
        out.write(f"   {_c('trigger', _DIM, use_color)}  {f.trigger}\n")
        out.write(f"   {_c('risk', _DIM, use_color)}     {f.danger}\n")
        if f.escalated:
            out.write(f"   {_c('escalated', _DIM, use_color)} {f.base_severity.label} → "
                      + _c(sev.label, _COLORS[sev], use_color) + " by code behaviour\n")
        if f.amplifiers:
            out.write(f"   {_c('signals', _DIM, use_color)}  ")
            out.write(", ".join(
                _c(f"{a.name} (+{a.weight})", _COLORS[Severity.HIGH], use_color)
                for a in f.amplifiers) + "\n")
        if f.snippet:
            out.write(f"   {_c('code', _DIM, use_color)}\n")
            for ln in f.snippet.splitlines()[:8]:
                out.write("   " + _c("│ ", _DIM, use_color) + ln + "\n")
        out.write(f"   {_c('fix', _DIM, use_color)}      {f.remediation}\n")

    out.write("\n" + _c("─" * (w + 2), _DIM, use_color) + "\n")
    out.write(f"{_BOLD if use_color else ''}{len(findings)} finding(s).{_RESET if use_color else ''} "
              f"Highest: " + _c(result.max_severity().label, _COLORS[result.max_severity()], use_color) + "\n\n")


def render_json(result: ScanResult, out: TextIO) -> None:
    payload = {
        "tool": "blastradius",
        "version": 1,
        "root": str(result.root),
        "files_scanned": result.files_scanned,
        "detectors_run": result.detectors_run,
        "summary": {
            sev.label: len(fs) for sev, fs in result.by_severity().items() if fs
        },
        "max_severity": result.max_severity().label,
        "findings": [f.to_dict() for f in result.findings],
    }
    json.dump(payload, out, indent=2)
    out.write("\n")


_SARIF_LEVEL = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.INFO: "note",
}


def render_sarif(result: ScanResult, out: TextIO) -> None:
    rules = {}
    results = []
    for f in result.findings:
        if f.vector_id not in rules:
            rules[f.vector_id] = {
                "id": f.vector_id,
                "name": f.title.replace(" ", ""),
                "shortDescription": {"text": f.title},
                "fullDescription": {"text": f.danger},
                "help": {"text": f.remediation},
                "defaultConfiguration": {"level": _SARIF_LEVEL[f.effective_severity]},
                "properties": {"ecosystem": f.ecosystem, "tags": ["auto-execution", f.ecosystem]},
            }
        msg = f.danger
        if f.amplifiers:
            msg += " Risk signals: " + ", ".join(a.name for a in f.amplifiers) + "."
        results.append({
            "ruleId": f.vector_id,
            "level": _SARIF_LEVEL[f.effective_severity],
            "message": {"text": msg},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": f.path},
                    "region": {"startLine": f.line or 1},
                }
            }],
            "properties": {
                "severity": f.effective_severity.label,
                "baseSeverity": f.base_severity.label,
                "amplifiers": [a.id for a in f.amplifiers],
            },
        })
    sarif = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {
                "name": "BlastRadius",
                "informationUri": "https://github.com/blastradius/blastradius",
                "version": "0.1.0",
                "rules": list(rules.values()),
            }},
            "results": results,
        }],
    }
    json.dump(sarif, out, indent=2)
    out.write("\n")
