"""Output renderers: terminal, JSON, SARIF, Markdown, HTML."""
from __future__ import annotations

import html
import json
import re
from typing import TextIO

from .models import Severity
from .scanner import ScanResult

SPONSOR_URL = "https://github.com/Aizosa/blastradius#support"

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
              f"Highest: " + _c(result.max_severity().label, _COLORS[result.max_severity()], use_color) + "\n")
    out.write(_c(f"BlastRadius is free & donation-funded — {SPONSOR_URL}", _DIM, use_color) + "\n\n")


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


_MD_ICON = {
    Severity.CRITICAL: "🔴", Severity.HIGH: "🟠", Severity.MEDIUM: "🟡",
    Severity.LOW: "🔵", Severity.INFO: "⚪",
}


def render_markdown(result: ScanResult, out: TextIO) -> None:
    """PR-comment / CI-summary friendly Markdown."""
    findings = result.findings
    out.write("## 🧨 BlastRadius — auto-execution scan\n\n")
    out.write(f"Scanned **{result.files_scanned}** files with "
              f"**{result.detectors_run}** detectors.\n\n")
    if not findings:
        out.write("✅ **No auto-execution points found.**\n\n")
        out.write(f"<sub>BlastRadius is free & donation-funded — [support]({SPONSOR_URL})</sub>\n")
        return

    buckets = result.by_severity()
    out.write("| Severity | Count |\n|---|---|\n")
    for sev in (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW):
        n = len(buckets[sev])
        if n:
            out.write(f"| {_MD_ICON[sev]} {sev.label} | {n} |\n")
    out.write("\n")

    for f in findings:
        sev = f.effective_severity
        loc = html.escape(f.path) + (f":{f.line}" if f.line else "")
        out.write(f"<details><summary>{_MD_ICON[sev]} <strong>{sev.label}</strong> — "
                  f"{html.escape(f.title)} <code>{loc}</code></summary>\n\n")
        out.write(f"- **Trigger:** {html.escape(f.trigger)}\n")
        out.write(f"- **Risk:** {html.escape(f.danger)}\n")
        if f.escalated:
            out.write(f"- **Escalated:** {f.base_severity.label} → {sev.label} by code behaviour\n")
        if f.amplifiers:
            out.write("- **Signals:** " + ", ".join(f"{a.name} (+{a.weight})" for a in f.amplifiers) + "\n")
        out.write(f"- **Fix:** {html.escape(f.remediation)}\n")
        if f.snippet:
            # fence must be longer than any backtick run inside the snippet
            runs = re.findall(r"`+", f.snippet)
            ticks = max(3, (max((len(r) for r in runs), default=0) + 1))
            fence = "`" * ticks
            out.write("\n" + fence + "\n" + f.snippet + "\n" + fence + "\n")
        out.write("\n</details>\n\n")

    out.write(f"---\n<sub>BlastRadius is free & donation-funded — [support]({SPONSOR_URL})</sub>\n")


_HTML_COLOR = {
    Severity.CRITICAL: "#b3261e", Severity.HIGH: "#e8710a", Severity.MEDIUM: "#c99a06",
    Severity.LOW: "#1a73e8", Severity.INFO: "#5f6368",
}


def render_html(result: ScanResult, out: TextIO) -> None:
    """Self-contained static dashboard — no external assets, shareable as one file."""
    e = html.escape
    buckets = result.by_severity()
    cards = ""
    for sev in (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW):
        n = len(buckets[sev])
        cards += (
            f'<button class="card" data-sev="{sev.label}" style="border-color:{_HTML_COLOR[sev]}">'
            f'<span class="num" style="color:{_HTML_COLOR[sev]}">{n}</span>'
            f'<span class="lbl">{sev.label}</span></button>'
        )

    rows = ""
    for f in result.findings:
        sev = f.effective_severity
        amps = "".join(f'<span class="amp">{e(a.name)} +{a.weight}</span>' for a in f.amplifiers)
        esc = (f'<div class="esc">escalated {f.base_severity.label} → '
               f'<b style="color:{_HTML_COLOR[sev]}">{sev.label}</b> by code behaviour</div>') if f.escalated else ""
        loc = e(f.path) + (f":{f.line}" if f.line else "")
        rows += f"""
      <div class="finding" data-sev="{sev.label}">
        <div class="fhead">
          <span class="pill" style="background:{_HTML_COLOR[sev]}">{sev.label}</span>
          <span class="ftitle">{e(f.title)}</span>
          <code class="vid">{e(f.vector_id)}</code>
        </div>
        <div class="loc">{loc}</div>
        <div class="meta"><b>Trigger</b> {e(f.trigger)}</div>
        <div class="meta"><b>Risk</b> {e(f.danger)}</div>
        {esc}
        <div class="amps">{amps}</div>
        <pre>{e(f.snippet)}</pre>
        <div class="fix"><b>Fix</b> {e(f.remediation)}</div>
      </div>"""

    empty = '<p class="empty">✅ No auto-execution points found.</p>' if not result.findings else ""
    doc = f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>BlastRadius report</title>
<style>
  :root {{ color-scheme: light dark; }}
  * {{ box-sizing: border-box; }}
  body {{ font: 14px/1.5 ui-monospace, SFMono-Regular, Menlo, monospace; margin: 0; padding: 24px;
         background: #0d1117; color: #e6edf3; }}
  @media (prefers-color-scheme: light) {{ body {{ background:#fff; color:#1f2328; }} }}
  h1 {{ font-size: 20px; margin: 0 0 4px; }}
  .sub {{ opacity:.65; margin-bottom:18px; }}
  .cards {{ display:flex; gap:12px; flex-wrap:wrap; margin-bottom:20px; }}
  .card {{ display:flex; flex-direction:column; align-items:center; min-width:92px; padding:12px 16px;
          border:2px solid; border-radius:12px; background:transparent; color:inherit; cursor:pointer; font:inherit; }}
  .card.off {{ opacity:.3; }}
  .num {{ font-size:26px; font-weight:700; }}
  .lbl {{ font-size:11px; letter-spacing:.08em; opacity:.8; }}
  .finding {{ border:1px solid #30363d; border-radius:10px; padding:14px 16px; margin-bottom:14px; }}
  @media (prefers-color-scheme: light) {{ .finding {{ border-color:#d0d7de; }} }}
  .fhead {{ display:flex; align-items:center; gap:10px; flex-wrap:wrap; }}
  .pill {{ color:#fff; padding:2px 9px; border-radius:20px; font-size:11px; font-weight:700; }}
  .ftitle {{ font-weight:700; }}
  .vid {{ opacity:.55; font-size:12px; }}
  .loc {{ opacity:.8; margin:6px 0; }}
  .meta {{ margin:3px 0; }} .meta b, .fix b {{ opacity:.6; font-weight:600; margin-right:6px; }}
  .esc {{ margin:4px 0; opacity:.9; }}
  .amps {{ margin:8px 0; display:flex; gap:6px; flex-wrap:wrap; }}
  .amp {{ background:#e8710a22; border:1px solid #e8710a66; color:#e8710a; padding:1px 8px; border-radius:20px; font-size:11px; }}
  pre {{ background:#161b22; padding:10px 12px; border-radius:8px; overflow:auto; margin:8px 0; font-size:12.5px; }}
  @media (prefers-color-scheme: light) {{ pre {{ background:#f6f8fa; }} }}
  .fix {{ margin-top:6px; }}
  .empty {{ font-size:16px; opacity:.8; }}
  footer {{ opacity:.55; margin-top:24px; font-size:12px; }}
  a {{ color:#4493f8; }}
</style></head><body>
  <h1>🧨 BlastRadius report</h1>
  <div class="sub">{e(str(result.root))} · {result.files_scanned} files · {result.detectors_run} detectors · highest: {result.max_severity().label}</div>
  <div class="cards">{cards}</div>
  {empty}
  <div id="list">{rows}</div>
  <footer>Generated by <a href="{SPONSOR_URL}">BlastRadius</a> — free &amp; donation-funded. If it saved you a bad afternoon, consider sponsoring.</footer>
<script>
  const active = new Set();
  document.querySelectorAll('.card').forEach(c => c.addEventListener('click', () => {{
    const s = c.dataset.sev;
    if (active.has(s)) {{ active.delete(s); c.classList.add('off'); }}
    else {{ active.add(s); c.classList.remove('off'); }}
    // if none selected -> show all
    const show = active.size ? active : null;
    document.querySelectorAll('.finding').forEach(f => {{
      f.style.display = (!show || show.has(f.dataset.sev)) ? '' : 'none';
    }});
  }}));
</script>
</body></html>
"""
    out.write(doc)

