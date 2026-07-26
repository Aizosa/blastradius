"""Policy & custom rules — the open, per-repo version of "org policy".

A committed ``.blastradius.json`` lets a team encode decisions in-repo:
which vectors to ignore, per-vector severity overrides, path excludes, default
gate level, and their own regex-based custom detectors. No server, no account —
the policy travels with the code and runs in CI.
"""
from __future__ import annotations

import fnmatch
import json
import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterator

from .models import Finding, Severity
from .detectors import FileIndex, Vector, build_finding, find_line, snippet_of

DEFAULT_CONFIG_NAMES = (".blastradius.json", "blastradius.json")


@dataclass
class Config:
    exclude: list[str] = field(default_factory=list)
    ignore_vectors: list[str] = field(default_factory=list)
    ignore_fingerprints: list[str] = field(default_factory=list)
    severity_overrides: dict[str, str] = field(default_factory=dict)
    min_severity: str | None = None
    fail_on: str | None = None
    custom_rules: list[dict] = field(default_factory=list)
    source: str | None = None

    @property
    def overrides_as_severity(self) -> dict[str, Severity]:
        return {vid: Severity.from_hint(s) for vid, s in self.severity_overrides.items()}


def find_config(root: str | Path, explicit: str | None = None) -> str | None:
    if explicit:
        return explicit if Path(explicit).is_file() else None
    root = Path(root)
    for name in DEFAULT_CONFIG_NAMES:
        p = root / name
        if p.is_file():
            return str(p)
    return None


def load_config(path: str | Path) -> Config:
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError("config root must be a JSON object")

    def _list(key):
        v = data.get(key, []) or []
        if not isinstance(v, list):
            raise ValueError(f"'{key}' must be a list")
        return list(v)

    def _dict(key):
        v = data.get(key, {}) or {}
        if not isinstance(v, dict):
            raise ValueError(f"'{key}' must be an object")
        return dict(v)

    for skey in ("min_severity", "fail_on"):
        if data.get(skey) is not None and not isinstance(data.get(skey), str):
            raise ValueError(f"'{skey}' must be a string")

    return Config(
        exclude=_list("exclude"),
        ignore_vectors=_list("ignore_vectors"),
        ignore_fingerprints=_list("ignore_fingerprints"),
        severity_overrides=_dict("severity_overrides"),
        min_severity=data.get("min_severity"),
        fail_on=data.get("fail_on"),
        custom_rules=_list("custom_rules"),
        source=str(path),
    )


def _glob_match(rel_posix: str, base: str, pattern: str) -> bool:
    """fnmatch, but tolerant of a leading ``**/`` (which otherwise never
    matches repo-root files) and always also tries the basename."""
    cands = {pattern}
    if pattern.startswith("**/"):
        cands.add(pattern[3:])
    return any(fnmatch.fnmatch(rel_posix, c) or fnmatch.fnmatch(base, c) for c in cands)


def build_custom_detectors(rules: list[dict]):
    """Turn config custom_rules into detector callables (not globally registered)."""
    detectors = []
    for raw in rules:
        try:
            detectors.append(_make_rule_detector(raw))
        except (re.error, KeyError, ValueError):
            # a malformed rule shouldn't sink the scan; skip it
            continue
    return detectors


def _make_rule_detector(raw: dict):
    rid = raw["id"]
    globs = raw.get("files") or ["**/*"]
    if isinstance(globs, str):
        globs = [globs]
    pattern = re.compile(raw["pattern"], re.IGNORECASE | re.MULTILINE) if raw.get("pattern") else None
    vec = Vector(
        vector_id=rid,
        title=raw.get("title", rid),
        ecosystem=raw.get("ecosystem", "custom"),
        trigger=raw.get("trigger", "custom rule match"),
        danger=raw.get("danger", "Matched a repository-defined custom rule."),
        remediation=raw.get("remediation", "Review per your team's policy."),
        base_severity=raw.get("severity", "medium"),
    )

    def _detector(idx: FileIndex) -> Iterator[Finding]:
        for rel in idx.rel_paths:
            rel_posix = rel.replace(os.sep, "/")
            base = os.path.basename(rel_posix)
            if not any(_glob_match(rel_posix, base, g) for g in globs):
                continue
            code = idx.read(rel)
            if pattern is None:
                yield build_finding(vec, rel, code, snippet=snippet_of(code, 6))
                continue
            m = pattern.search(code)
            if m:
                yield build_finding(vec, rel, code,
                                    snippet=snippet_of(code, 6, around=m.group(0)),
                                    line=find_line(code, m.group(0)), scan_text=code)

    _detector.__name__ = f"custom_{rid}".replace("-", "_")
    return _detector
