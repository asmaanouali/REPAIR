"""Stable, web-facing API facade over the IR-SAM pipeline.

The web backend (``apps/api``) and worker (``apps/worker``) MUST go
through this module instead of importing from ``core.pipeline``,
``core.ingest``, etc. directly. This keeps the research-grade core
free to evolve while giving the productionized layer a stable seam.

Only **additive** wrappers live here. Existing modules are untouched.
"""

from __future__ import annotations

from .facade import (
    FindingRecord,
    GateRecord,
    PatchRecord,
    PipelineEvent,
    QuickfixOptions,
    QuickfixResult,
    ScanOptions,
    ScanRecord,
    generate_patch_for_file,
    import_sarif_bytes,
    run_quickfix,
    run_scan_findings,
    run_scan_path,
)

__all__ = [
    "FindingRecord",
    "GateRecord",
    "PatchRecord",
    "PipelineEvent",
    "QuickfixOptions",
    "QuickfixResult",
    "ScanOptions",
    "ScanRecord",
    "generate_patch_for_file",
    "import_sarif_bytes",
    "run_quickfix",
    "run_scan_findings",
    "run_scan_path",
]
