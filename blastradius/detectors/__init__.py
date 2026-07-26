"""Detector infrastructure: file index, vector definitions, registry.

A *detector* is a function that takes a :class:`FileIndex` and yields
:class:`~blastradius.models.Finding` objects. Each detector knows one family
of auto-execution points. The registry collects them so the scanner can run
every detector over a repo in one pass.
"""
from __future__ import annotations

import fnmatch
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Iterator

from ..models import Finding, Severity
from ..risk import escalate, scan_amplifiers

# Directories we never descend into (huge / vendored / generated), EXCEPT we
# still want a couple of paths inside .git — handled specially in the walker.
_SKIP_DIRS = {
    "node_modules", ".venv", "venv", "env", "vendor", "dist", "build",
    ".mypy_cache", "__pycache__", ".pytest_cache", "target", ".gradle",
    ".next", ".turbo", ".cache", "coverage", ".idea/caches",
}
_MAX_READ = 512 * 1024


class FileIndex:
    """Walks a repo once and offers cheap lookups by name / glob."""

    def __init__(self, root: Path, excludes: list[str] | None = None, _skip_walk: bool = False):
        self.root = root.resolve()
        self.excludes = list(excludes or [])
        self.rel_paths: list[str] = []
        self._abs: dict[str, Path] = {}
        self._by_name: dict[str, list[str]] = {}
        self._cache: dict[str, str] = {}
        if not _skip_walk:
            self._build()

    @classmethod
    def from_files(cls, root: Path, rel_paths: list[str]) -> "FileIndex":
        """Build an index over an explicit list of files (relative to root).

        Used for targeted scopes like --include-home, where walking the whole
        tree would be slow and unsafe; only the listed files are indexed.
        """
        idx = cls(root, _skip_walk=True)
        for rel in rel_paths:
            abs_p = (idx.root / rel)
            try:
                if not abs_p.is_file():
                    continue
            except OSError:
                continue
            rel_norm = os.path.normpath(rel)
            idx.rel_paths.append(rel_norm)
            idx._abs[rel_norm] = abs_p
            idx._by_name.setdefault(os.path.basename(rel_norm), []).append(rel_norm)
        return idx

    def _excluded(self, rel: str) -> bool:
        rel_posix = rel.replace(os.sep, "/")
        for pat in self.excludes:
            p = pat.replace(os.sep, "/").rstrip("/")
            if rel_posix == p or rel_posix.startswith(p + "/") or fnmatch.fnmatch(rel_posix, pat):
                return True
        return False

    def _build(self) -> None:
        root = self.root
        for dirpath, dirnames, filenames in os.walk(root):
            rel_dir = os.path.relpath(dirpath, root)
            parts = [] if rel_dir == "." else rel_dir.split(os.sep)
            # Special handling for .git: keep only hooks/ and config.
            if parts and parts[0] == ".git":
                if not (parts[:2] == [".git", "hooks"] or parts == [".git"]):
                    dirnames[:] = []
                    if not (len(parts) >= 2 and parts[1] == "hooks"):
                        continue
            else:
                dirnames[:] = [
                    d for d in dirnames
                    if d not in _SKIP_DIRS
                    and not _skip_symlink(dirpath, d)
                    and not self._excluded(os.path.relpath(os.path.join(dirpath, d), root))
                ]
            for fn in filenames:
                if parts == [".git"] and fn != "config":
                    continue
                abs_p = Path(dirpath) / fn
                rel = os.path.relpath(abs_p, root)
                if self._excluded(rel):
                    continue
                self.rel_paths.append(rel)
                self._abs[rel] = abs_p
                self._by_name.setdefault(fn, []).append(rel)

    def by_name(self, *names: str) -> list[str]:
        out: list[str] = []
        for n in names:
            out.extend(self._by_name.get(n, []))
        return out

    def by_suffix(self, *suffixes: str) -> list[str]:
        return [r for r in self.rel_paths if r.endswith(suffixes)]

    def under(self, prefix: str) -> list[str]:
        prefix = prefix.replace("/", os.sep)
        return [r for r in self.rel_paths if r == prefix or r.startswith(prefix + os.sep)]

    def abs(self, rel: str) -> Path:
        return self._abs[rel]

    def read(self, rel: str) -> str:
        if rel in self._cache:
            return self._cache[rel]
        text = ""
        try:
            p = self._abs[rel]
            if p.is_file() and p.stat().st_size <= _MAX_READ:
                text = p.read_text(encoding="utf-8", errors="replace")
        except (OSError, ValueError):
            text = ""
        self._cache[rel] = text
        return text


def _skip_symlink(dirpath: str, name: str) -> bool:
    try:
        return os.path.islink(os.path.join(dirpath, name))
    except OSError:
        return False


@dataclass(frozen=True)
class Vector:
    """Static metadata for one class of auto-execution point."""

    vector_id: str
    title: str
    ecosystem: str
    trigger: str
    danger: str
    remediation: str
    base_severity: str  # low|medium|high|critical


def find_line(text: str, needle: str) -> int | None:
    if not needle:
        return None
    idx = text.find(needle)
    if idx < 0:
        return None
    return text.count("\n", 0, idx) + 1


def snippet_of(text: str, max_lines: int = 6, around: str = "") -> str:
    lines = text.splitlines()
    if around:
        ln = find_line(text, around)
        if ln:
            lo = max(0, ln - 2)
            hi = min(len(lines), ln + max_lines - 1)
            return "\n".join(lines[lo:hi]).strip()
    return "\n".join(lines[:max_lines]).strip()


def build_finding(
    vec: Vector,
    path: str,
    code: str,
    *,
    snippet: str = "",
    line: int | None = None,
    scan_text: str | None = None,
) -> Finding:
    """Assemble a Finding, running amplifiers over ``scan_text`` (defaults to code)."""
    amps = scan_amplifiers(scan_text if scan_text is not None else code)
    base = Severity.from_hint(vec.base_severity)
    eff = escalate(base, amps)
    if not snippet:
        snippet = snippet_of(code)
    return Finding(
        vector_id=vec.vector_id,
        title=vec.title,
        ecosystem=vec.ecosystem,
        path=path,
        trigger=vec.trigger,
        danger=vec.danger,
        remediation=vec.remediation,
        base_severity=base,
        effective_severity=eff,
        line=line,
        snippet=snippet,
        amplifiers=amps,
    )


# --- registry -----------------------------------------------------------------

Detector = Callable[[FileIndex], Iterator[Finding]]
_REGISTRY: list[Detector] = []


def detector(fn: Detector) -> Detector:
    _REGISTRY.append(fn)
    return fn


def all_detectors() -> list[Detector]:
    return list(_REGISTRY)
