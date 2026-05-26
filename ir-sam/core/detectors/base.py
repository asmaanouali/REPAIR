"""Detector protocol + shared result types."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Protocol

from core.ingest.unified import IRSAMFinding


class DetectorError(RuntimeError):
    """Raised when a detector subprocess fails fatally (non-skippable)."""


@dataclass(frozen=True)
class DetectorUnavailable:
    """Typed "skipped" outcome: the detector binary is not installed
    or is not enabled by the current configuration.
    """

    detector: str
    reason: str


@dataclass(frozen=True)
class DetectorOutcome:
    """Successful detector run: zero or more findings plus diagnostics."""

    detector: str
    findings: tuple[IRSAMFinding, ...] = field(default_factory=tuple)
    sarif_path: str | None = None
    stderr_tail: str = ""

    @property
    def empty(self) -> bool:
        return not self.findings


class Detector(Protocol):
    """Minimal interface every detector runner must satisfy."""

    name: str

    def is_available(self) -> bool:
        ...

    def scan(self, workdir: Path,
             languages: tuple[str, ...] = ()) -> DetectorOutcome | DetectorUnavailable:
        """Run the detector against ``workdir``.

        ``languages`` is an optional hint (e.g. ``("java",)``). Runners
        that cannot honor the hint should scan the full workdir.
        """
        ...
