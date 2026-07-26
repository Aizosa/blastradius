"""Scan orchestration: run every detector over a repo and rank findings."""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from .detectors import FileIndex, all_detectors
from .detectors import builtins as _builtins  # noqa: F401  (registers detectors)
from .detectors import extras as _extras  # noqa: F401  (registers detectors)
from .detectors import catalog as _catalog  # noqa: F401  (registers detectors)
from .models import Finding, Severity


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


def scan(root: str | Path, excludes: list[str] | None = None) -> ScanResult:
    root_path = Path(root)
    if not root_path.exists():
        raise FileNotFoundError(f"path does not exist: {root}")
    idx = FileIndex(root_path, excludes=excludes)
    detectors = all_detectors()
    findings: list[Finding] = []
    for det in detectors:
        try:
            findings.extend(det(idx))
        except Exception:  # a broken detector must never sink the whole scan
            continue
    findings.sort(
        key=lambda f: (
            -int(f.effective_severity),
            -sum(a.weight for a in f.amplifiers),
            f.ecosystem,
            f.path,
        )
    )
    return ScanResult(
        root=idx.root,
        findings=findings,
        files_scanned=len(idx.rel_paths),
        detectors_run=len(detectors),
    )
