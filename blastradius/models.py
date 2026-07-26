"""Core data model for BlastRadius findings."""
from __future__ import annotations

import enum
import hashlib
from dataclasses import dataclass, field, asdict
from typing import Optional


class Severity(enum.IntEnum):
    """Ordered so that comparisons and sorting are meaningful."""

    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @classmethod
    def from_hint(cls, hint: str) -> "Severity":
        return {
            "info": cls.INFO,
            "low": cls.LOW,
            "medium": cls.MEDIUM,
            "high": cls.HIGH,
            "critical": cls.CRITICAL,
        }.get((hint or "").strip().lower(), cls.MEDIUM)

    @property
    def label(self) -> str:
        return self.name


@dataclass
class Amplifier:
    """A cross-cutting risk signal found inside an auto-run file."""

    id: str
    name: str
    weight: int
    why: str
    evidence: str = ""


@dataclass
class Finding:
    """One place code can execute without an explicit human yes."""

    vector_id: str
    title: str
    ecosystem: str
    path: str
    trigger: str
    danger: str
    remediation: str
    base_severity: Severity
    effective_severity: Severity
    line: Optional[int] = None
    snippet: str = ""
    amplifiers: list[Amplifier] = field(default_factory=list)

    @property
    def escalated(self) -> bool:
        return self.effective_severity > self.base_severity

    @property
    def fingerprint(self) -> str:
        """Stable id for baseline matching — survives line moves and re-runs.

        Keyed on what the finding *is* (vector + location + the flagged code),
        not on line number or severity, so accepting a baseline entry keeps
        holding as long as the underlying auto-run point is unchanged.
        """
        norm = " ".join((self.snippet or "").split())
        h = hashlib.sha1(f"{self.vector_id}\0{self.path}\0{norm}".encode("utf-8", "replace"))
        return h.hexdigest()[:16]

    def to_dict(self) -> dict:
        d = asdict(self)
        d["base_severity"] = self.base_severity.label
        d["effective_severity"] = self.effective_severity.label
        d["fingerprint"] = self.fingerprint
        return d
