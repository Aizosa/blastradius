"""Scan orchestration: run every detector over a repo and rank findings."""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Iterable

from .detectors import FileIndex, all_detectors
from .detectors import builtins as _builtins  # noqa: F401  (registers detectors)
from .detectors import extras as _extras  # noqa: F401  (registers detectors)
from .detectors import catalog as _catalog  # noqa: F401  (registers detectors)
from .models import Finding, Severity
from .risk import escalate

# A curated allowlist of user-level config files scanned by --include-home.
# Kept explicit (not a walk of $HOME) so the home scan stays fast and safe.
HOME_FILES = [
    ".gitconfig", ".config/git/config",
    ".claude/settings.json", ".claude/settings.local.json",
    ".npmrc", ".yarnrc", ".yarnrc.yml",
    ".ssh/config",
    ".gdbinit", ".lldbinit",
    ".bashrc", ".zshrc", ".bash_profile", ".profile", ".zprofile", ".zshenv",
    ".Rprofile",
    ".gitattributes", ".config/git/attributes",
    ".pip/pip.conf", ".config/pip/pip.conf",
    ".cargo/config.toml", ".cargo/config",
    ".cursorrules", ".config/direnv/direnvrc",
]


@dataclass
class ScanResult:
    root: Path
    findings: list[Finding]
    files_scanned: int
    detectors_run: int

    def by_severity(self) -> dict[Severity, list[Finding]]:
        out: dict[Severity, list[Finding]] = {s: [] for s in reversed(Severity)}
        for f in self.findings:
            out[f.effective_severity].append(f)
        return out

    def max_severity(self) -> Severity:
        return max((f.effective_severity for f in self.findings), default=Severity.INFO)

    def count_at_or_above(self, level: Severity) -> int:
        return sum(1 for f in self.findings if f.effective_severity >= level)


def _sort_key(f: Finding):
    return (-int(f.effective_severity), -sum(a.weight for a in f.amplifiers), f.ecosystem, f.path)


def _run_detectors(idx: FileIndex, detectors: list[Callable]) -> list[Finding]:
    findings: list[Finding] = []
    for det in detectors:
        try:
            findings.extend(det(idx))
        except Exception:  # a broken detector must never sink the whole scan
            continue
    return findings


def _apply_policy(
    findings: list[Finding],
    severity_overrides: dict[str, Severity] | None,
    ignore_vectors: Iterable[str] | None,
    ignore_fingerprints: Iterable[str] | None,
) -> list[Finding]:
    ignore_v = set(ignore_vectors or ())
    ignore_f = set(ignore_fingerprints or ())
    overrides = severity_overrides or {}
    out = []
    for f in findings:
        if f.vector_id in ignore_v or f.fingerprint in ignore_f:
            continue
        if f.vector_id in overrides:
            # Override sets the *baseline* for this vector; code-behaviour
            # amplifiers can still escalate above it. A security tool must not
            # let policy silently downgrade a live, amplifier-escalated RCE.
            f.base_severity = overrides[f.vector_id]
            f.effective_severity = escalate(overrides[f.vector_id], f.amplifiers)
        out.append(f)
    return out


def scan(
    root: str | Path,
    excludes: list[str] | None = None,
    *,
    extra_detectors: list[Callable] | None = None,
    severity_overrides: dict[str, Severity] | None = None,
    ignore_vectors: Iterable[str] | None = None,
    ignore_fingerprints: Iterable[str] | None = None,
    include_home: bool = False,
) -> ScanResult:
    root_path = Path(root)
    if not root_path.exists():
        raise FileNotFoundError(f"path does not exist: {root}")

    detectors = all_detectors() + list(extra_detectors or [])
    idx = FileIndex(root_path, excludes=excludes)
    findings = _run_detectors(idx, detectors)
    files_scanned = len(idx.rel_paths)

    if include_home:
        home = Path.home()
        home_idx = FileIndex.from_files(home, HOME_FILES)
        for f in _run_detectors(home_idx, detectors):
            # show a ~/-relative path: readable, portable, and no username leak
            f.path = "~/" + f.path.replace("\\", "/")
            findings.append(f)
        files_scanned += len(home_idx.rel_paths)

    findings = _apply_policy(findings, severity_overrides, ignore_vectors, ignore_fingerprints)
    findings.sort(key=_sort_key)
    return ScanResult(
        root=idx.root,
        findings=findings,
        files_scanned=files_scanned,
        detectors_run=len(detectors),
    )
