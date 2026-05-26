"""Real detector runners (Phase 6).

The MVP shipped a regex-based ``run_resast_gate`` that scanned patched
Java source for residual ``executeQuery("..." + ...)`` shapes. That is
a string-matcher, not a static-analysis re-run.

This package wires real detector subprocesses into the validator
pipeline:

* :mod:`core.detectors.semgrep_runner` --- Semgrep CLI; always
  attempted if ``semgrep`` is on ``$PATH``.
* :mod:`core.detectors.codeql_runner`  --- CodeQL CLI; only attempted
  when the ``IRSAM_CODEQL_BIN`` environment variable points to a
  ``codeql`` binary.

Both runners shell out, parse the produced SARIF document through the
existing :mod:`core.ingest` adapters, and return a list of
:class:`~core.ingest.unified.IRSAMFinding`.

If the binary is unavailable, runners return
:class:`DetectorUnavailable` (a typed "skipped" outcome) instead of
raising; the validator can then degrade gracefully to the regex
fallback or surface a typed soft-fail.
"""

from .base import (
    Detector,
    DetectorError,
    DetectorOutcome,
    DetectorUnavailable,
)

__all__ = [
    "Detector",
    "DetectorError",
    "DetectorOutcome",
    "DetectorUnavailable",
]
