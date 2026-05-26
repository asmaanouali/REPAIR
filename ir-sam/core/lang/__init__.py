"""Multi-language frontend (Phase 4).

This package adds Python host-language support to the IR-SAM
pipeline. The architecture is deliberately symmetric with the Java
pipeline (``core.slicer``, ``core.recon``, ``core.rewriter``): each
language module exposes::

    slice_sink_argument(src, sink_line) -> SliceResult | SliceAbstention
    synthesize_patch(src, slice, plan)  -> PatchResult | RewriteAbstention
    SINK_APIS                            -> set[str]
    PLACEHOLDER_STYLE                    -> str

so the orchestrator can dispatch by file extension. The reused
:class:`core.slicer.StringPart` / :class:`core.slicer.SliceResult`
types keep Stage C and Stage D fully language-agnostic.

Supported sinks:

* Python (``.py``): ``cursor.execute``, ``cursor.executemany``,
  ``ldap3.Connection.search``, ``lxml.etree.XPath()`` and the
  Phase-9 sink families (subprocess, deserialization, path, SSTI).

The Python backend uses :mod:`libcst` when available and falls back
to a deterministic regex slicer (the same shape as the Java MVP
slicer) otherwise.

Java is handled by :mod:`core.lang.java`. JavaScript/TypeScript is
not supported: IR-SAM remediates Java and Python sources only.
"""

from __future__ import annotations

from pathlib import Path
from enum import Enum


class Language(str, Enum):
    JAVA = "java"
    PYTHON = "python"

    @staticmethod
    def from_path(p: Path | str) -> "Language":
        s = str(p).lower()
        if s.endswith(".java"):
            return Language.JAVA
        if s.endswith(".py"):
            return Language.PYTHON
        raise ValueError(f"unsupported language for {p}")


__all__ = ["Language"]
