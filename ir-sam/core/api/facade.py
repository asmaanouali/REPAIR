"""Concrete facade implementations.

Design rules
------------

* No mutation of existing ``core.*`` modules.
* Pure dataclasses with primitive fields → trivially JSON-serializable.
* Streaming surface uses an ``Iterator[PipelineEvent]`` so the worker can
  forward progress to a websocket without re-parsing IR-SAM internals.
* No imports of ``fastapi``, ``sqlalchemy``, or any web frameworks --
  this layer must remain runnable from a plain ``python`` shell.
"""

from __future__ import annotations

import json
import tempfile
import time
import uuid
from collections.abc import Iterable, Iterator
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Literal

from core.ingest import codeql as _codeql_adapter
from core.ingest import semgrep as _semgrep_adapter
from core.ingest import sonarqube as _sonarqube_adapter
from core.artifacts import resolve_finding_path
from core.ingest.unified import IRSAMFinding, dedup_findings
from core.pipeline import PipelineOutcome, run_file, run_finding


# ---------------------------------------------------------------------------
# Serializable records
# ---------------------------------------------------------------------------


SupportedLanguage = Literal["java"]


@dataclass(frozen=True)
class QuickfixOptions:
    language: SupportedLanguage = "java"
    catalog_path: str | None = None
    allowlists: dict[str, str] = field(default_factory=dict)


@dataclass(frozen=True)
class GateRecord:
    name: str
    passed: bool
    detail: str = ""


@dataclass(frozen=True)
class PatchRecord:
    file: str
    stage_reached: str
    patched: bool
    all_gates_passed: bool
    abstention_reason: str | None
    unified_diff: str | None
    patched_source: str | None
    prepared_template: str | None
    binders_used: list[str]
    gates: list[GateRecord]

    #: Phase 9 honesty surface.
    #:
    #: One of:
    #:
    #: * ``"proven"``         – patch validated by all gates AND the
    #:   binder's `proof_obligation` is discharged by an active Lean
    #:   axiom/theorem.
    #: * ``"axiomatized"``    – patch validated, proof obligation
    #:   references a Lean axiom (assumption made explicit).
    #: * ``"validated_only"`` – patch validated empirically (gates
    #:   green) but no formal proof obligation exists for this binder.
    #: * ``"best_effort"``    – pipeline abstained; the patch is a
    #:   commented hint, not a real fix.
    #: * ``"unverified"``     – pipeline emitted code but ≥1 gate
    #:   failed or was soft-failed (e.g. TEST_REGRESSION_NOT_CONFIGURED).
    proof_status: str = "unverified"

    #: Free-text qualifier always paired with the verbal claim, e.g.
    #: "provably safe within assumptions §A.2 (JDBC PreparedStatement
    #: inertness, identifier-allowlist closure)".
    safety_claim: str = ""

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["gates"] = [asdict(g) for g in self.gates]
        return d


@dataclass(frozen=True)
class QuickfixResult:
    request_id: str
    language: SupportedLanguage
    elapsed_ms: int
    result: PatchRecord

    def to_dict(self) -> dict[str, Any]:
        return {
            "request_id": self.request_id,
            "language": self.language,
            "elapsed_ms": self.elapsed_ms,
            "result": self.result.to_dict(),
        }


@dataclass(frozen=True)
class FindingRecord:
    finding_id: str
    detector: str
    detector_rule_id: str
    cwe: list[str]
    language: str
    interpreter: str
    file: str
    line_start: int
    line_end: int | None
    sink_api: str
    severity: str | None

    @classmethod
    def from_irsam(cls, f: IRSAMFinding) -> "FindingRecord":
        return cls(
            finding_id=f.finding_id,
            detector=str(f.detector),
            detector_rule_id=f.detector_rule_id,
            cwe=list(f.cwe),
            language=str(f.language),
            interpreter=str(f.interpreter),
            file=f.location.file,
            line_start=f.location.line_start,
            line_end=f.location.line_end,
            sink_api=f.sink.api_qualified_name,
            severity=str(f.severity) if f.severity else None,
        )

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class ScanOptions:
    languages: tuple[SupportedLanguage, ...] = ("java",)
    include_globs: tuple[str, ...] = ()
    exclude_globs: tuple[str, ...] = (
        "**/.git/**", "**/node_modules/**", "**/.venv/**", "**/build/**",
        "**/dist/**", "**/target/**", "**/__pycache__/**",
    )
    catalog_path: str | None = None
    allowlists: dict[str, str] = field(default_factory=dict)
    # If True, immediately try to synthesize a patch for each discovered
    # candidate sink. Worker uses False for "scan only" runs and calls
    # ``generate_patch_for_file`` later on demand.
    generate_patches: bool = True


@dataclass(frozen=True)
class ScanRecord:
    scan_id: str
    root: str
    files_examined: int
    findings: list[FindingRecord]
    patches: list[PatchRecord]
    elapsed_ms: int

    def to_dict(self) -> dict[str, Any]:
        return {
            "scan_id": self.scan_id,
            "root": self.root,
            "files_examined": self.files_examined,
            "findings": [f.to_dict() for f in self.findings],
            "patches": [p.to_dict() for p in self.patches],
            "elapsed_ms": self.elapsed_ms,
        }


@dataclass(frozen=True)
class PipelineEvent:
    """Streamed progress event for a single scan."""

    kind: Literal[
        "scan_started",
        "file_started",
        "file_skipped",
        "stage_reached",
        "patch_ready",
        "gate_result",
        "file_finished",
        "scan_finished",
        "error",
    ]
    timestamp: float
    payload: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


_LANG_TO_SUFFIXES: dict[str, tuple[str, ...]] = {
    "java": (".java",),
}


def _suffix_to_language(suffix: str) -> SupportedLanguage | None:
    for lang, sfx in _LANG_TO_SUFFIXES.items():
        if suffix in sfx:
            return lang  # type: ignore[return-value]
    return None


def _outcome_to_patch(outcome: PipelineOutcome) -> PatchRecord:
    unified_diff = outcome.patch.unified_diff if outcome.patch else None
    patched_source = outcome.patch.patched_source if outcome.patch else None
    abstention_reason = outcome.abstention_reason

    # Phase 10: the legacy best-effort *diff* fallback was removed --
    # IR-SAM no longer emits a commented-hint patch above the sink. The
    # honest equivalent is ``proof_status == "best_effort"`` (see
    # ``core.api.honesty.compute_proof_status``), which downstream UI
    # surfaces consume directly.

    # Phase 9: compute the honest proof_status + safety_claim.
    from core.api.honesty import GateLike, compute_proof_status

    gate_likes = tuple(
        GateLike(name=g.name, passed=g.passed, detail=g.detail)
        for g in (outcome.gates.gates if outcome.gates else ())
    )
    obligations = outcome.extra.get("proof_obligations", ())
    proof_status, safety_claim = compute_proof_status(
        stage_reached=outcome.stage_reached,
        patched=unified_diff is not None,
        gates=gate_likes,
        proof_obligations=obligations,
        abstention_reason=abstention_reason,
    )

    return PatchRecord(
        file=outcome.file,
        stage_reached=outcome.stage_reached,
        patched=unified_diff is not None,
        all_gates_passed=outcome.all_gates_passed,
        abstention_reason=abstention_reason,
        unified_diff=unified_diff,
        patched_source=patched_source,
        prepared_template=(outcome.plan.prepared_template if outcome.plan else None),
        binders_used=(list(outcome.plan.binder_ids_used) if outcome.plan else []),
        gates=[
            GateRecord(name=g.name, passed=g.passed, detail=g.detail)
            for g in (outcome.gates.gates if outcome.gates else ())
        ],
        proof_status=proof_status,
        safety_claim=safety_claim,
    )


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def run_quickfix(source: str, options: QuickfixOptions | None = None) -> QuickfixResult:
    """Run the full A..G pipeline against an in-memory source snippet.

    The source is written to a temporary file with the appropriate
    suffix for the requested language, then handed to
    :func:`core.pipeline.run_file`.
    """
    opts = options or QuickfixOptions()
    suffixes = _LANG_TO_SUFFIXES.get(opts.language, (".java",))
    suffix = suffixes[0]
    request_id = uuid.uuid4().hex
    started = time.perf_counter()
    with tempfile.TemporaryDirectory() as tmp:
        fp = Path(tmp) / f"Quickfix_{request_id[:8]}{suffix}"
        fp.write_text(source, encoding="utf-8")
        outcome = run_file(
            fp,
            catalog_path=Path(opts.catalog_path) if opts.catalog_path else None,
            allowlists=dict(opts.allowlists) or None,
        )
    elapsed_ms = int((time.perf_counter() - started) * 1000)
    return QuickfixResult(
        request_id=request_id,
        language=opts.language,
        elapsed_ms=elapsed_ms,
        result=_outcome_to_patch(outcome),
    )


def generate_patch_for_file(
    path: str | Path, options: QuickfixOptions | None = None
) -> PatchRecord:
    """Run A..G on an on-disk file (used by worker for per-finding patches)."""
    opts = options or QuickfixOptions()
    outcome = run_file(
        Path(path),
        catalog_path=Path(opts.catalog_path) if opts.catalog_path else None,
        allowlists=dict(opts.allowlists) or None,
    )
    return _outcome_to_patch(outcome)


def _iter_source_files(root: Path, options: ScanOptions) -> Iterator[Path]:
    allowed_suffixes: set[str] = set()
    for lang in options.languages:
        allowed_suffixes.update(_LANG_TO_SUFFIXES.get(lang, ()))
    for p in root.rglob("*"):
        if not p.is_file():
            continue
        if p.suffix not in allowed_suffixes:
            continue
        # Exclusions
        rel = p.relative_to(root).as_posix()
        skip = False
        for pat in options.exclude_globs:
            if p.match(pat) or Path(rel).match(pat):
                skip = True
                break
        if skip:
            continue
        if options.include_globs:
            if not any(p.match(g) or Path(rel).match(g) for g in options.include_globs):
                continue
        yield p


def run_scan_path(
    root: str | Path,
    options: ScanOptions | None = None,
    *,
    scan_id: str | None = None,
) -> Iterator[PipelineEvent]:
    """Yield :class:`PipelineEvent` objects as the scan progresses.

    Consumers should drain the iterator to completion. The final event
    is always ``scan_finished`` and carries a JSON-serializable
    :class:`ScanRecord` in its payload under the ``record`` key.
    """
    opts = options or ScanOptions()
    sid = scan_id or uuid.uuid4().hex
    root_path = Path(root).resolve()
    started = time.perf_counter()
    findings: list[FindingRecord] = []
    patches: list[PatchRecord] = []
    files_examined = 0

    yield PipelineEvent("scan_started", time.time(),
                        {"scan_id": sid, "root": str(root_path),
                         "languages": list(opts.languages)})

    if not root_path.exists():
        yield PipelineEvent("error", time.time(),
                            {"scan_id": sid, "message": f"root not found: {root_path}"})
        record = ScanRecord(sid, str(root_path), 0, findings, patches,
                            int((time.perf_counter() - started) * 1000))
        yield PipelineEvent("scan_finished", time.time(),
                            {"scan_id": sid, "record": record.to_dict()})
        return

    for file_path in _iter_source_files(root_path, opts):
        files_examined += 1
        lang = _suffix_to_language(file_path.suffix) or "java"
        yield PipelineEvent("file_started", time.time(),
                            {"scan_id": sid, "file": str(file_path), "language": lang})
        try:
            outcome = run_file(
                file_path,
                catalog_path=Path(opts.catalog_path) if opts.catalog_path else None,
                allowlists=dict(opts.allowlists) or None,
            )
        except Exception as exc:  # noqa: BLE001 -- boundary
            yield PipelineEvent("error", time.time(),
                                {"scan_id": sid, "file": str(file_path),
                                 "exception": repr(exc)})
            continue

        yield PipelineEvent("stage_reached", time.time(),
                            {"scan_id": sid, "file": str(file_path),
                             "stage": outcome.stage_reached,
                             "abstention_reason": outcome.abstention_reason})

        if outcome.stage_reached == "A" and outcome.abstention_reason == "no_sink_found":
            yield PipelineEvent("file_finished", time.time(),
                                {"scan_id": sid, "file": str(file_path),
                                 "had_finding": False})
            continue

        finding = FindingRecord(
            finding_id=uuid.uuid4().hex,
            detector="ir-sam",
            detector_rule_id="cwe-89-builtin-scan",
            cwe=["CWE-89"],
            language=lang,
            interpreter="sql",
            file=str(file_path),
            line_start=outcome.sink_line or 1,
            line_end=outcome.sink_line,
            sink_api=(outcome.slice_result.sink_call_text
                      if outcome.slice_result else "unknown"),
            severity="high",
        )
        findings.append(finding)

        if opts.generate_patches:
            patch = _outcome_to_patch(outcome)
            patches.append(patch)
            yield PipelineEvent("patch_ready", time.time(),
                                {"scan_id": sid, "file": str(file_path),
                                 "patch": patch.to_dict()})
            for g in patch.gates:
                yield PipelineEvent("gate_result", time.time(),
                                    {"scan_id": sid, "file": str(file_path),
                                     "name": g.name, "passed": g.passed,
                                     "detail": g.detail})

        yield PipelineEvent("file_finished", time.time(),
                            {"scan_id": sid, "file": str(file_path),
                             "had_finding": True})

    elapsed_ms = int((time.perf_counter() - started) * 1000)
    record = ScanRecord(sid, str(root_path), files_examined, findings,
                        patches, elapsed_ms)
    yield PipelineEvent("scan_finished", time.time(),
                        {"scan_id": sid, "record": record.to_dict()})


def run_scan_findings(
    root: str | Path,
    findings: Iterable[IRSAMFinding],
    options: ScanOptions | None = None,
    *,
    scan_id: str | None = None,
) -> Iterator[PipelineEvent]:
    """Run the pipeline for normalized detector findings under a project root."""
    opts = options or ScanOptions()
    sid = scan_id or uuid.uuid4().hex
    root_path = Path(root).resolve()
    started = time.perf_counter()
    normalized = dedup_findings(findings)
    finding_rows: list[FindingRecord] = []
    patches: list[PatchRecord] = []
    files_seen: set[str] = set()

    yield PipelineEvent("scan_started", time.time(),
                        {"scan_id": sid, "root": str(root_path),
                         "source": "findings", "finding_count": len(normalized)})

    if not root_path.exists():
        yield PipelineEvent("error", time.time(),
                            {"scan_id": sid, "message": f"root not found: {root_path}"})
        record = ScanRecord(sid, str(root_path), 0, finding_rows, patches,
                            int((time.perf_counter() - started) * 1000))
        yield PipelineEvent("scan_finished", time.time(),
                            {"scan_id": sid, "record": record.to_dict()})
        return

    for finding in normalized:
        source_path = resolve_finding_path(root_path, finding)
        files_seen.add(str(source_path))
        if finding.language not in opts.languages:
            yield PipelineEvent("file_skipped", time.time(),
                                {"scan_id": sid,
                                 "finding_id": finding.finding_id,
                                 "file": str(source_path),
                                 "language": finding.language,
                                 "reason": "language_filtered"})
            continue

        finding_row = FindingRecord.from_irsam(finding)
        finding_rows.append(finding_row)
        yield PipelineEvent("file_started", time.time(),
                            {"scan_id": sid,
                             "finding_id": finding.finding_id,
                             "file": str(source_path),
                             "language": finding.language,
                             "interpreter": finding.interpreter})
        try:
            outcome = run_finding(
                root_path,
                finding,
                catalog_path=Path(opts.catalog_path) if opts.catalog_path else None,
                allowlists=dict(opts.allowlists) or None,
            )
        except Exception as exc:  # noqa: BLE001 -- API boundary
            yield PipelineEvent("error", time.time(),
                                {"scan_id": sid,
                                 "finding_id": finding.finding_id,
                                 "file": str(source_path),
                                 "exception": repr(exc)})
            continue

        yield PipelineEvent("stage_reached", time.time(),
                            {"scan_id": sid,
                             "finding_id": finding.finding_id,
                             "job_id": outcome.extra.get("job_id"),
                             "artifact_id": outcome.extra.get("artifact_id"),
                             "file": str(source_path),
                             "stage": outcome.stage_reached,
                             "abstention_reason": outcome.abstention_reason,
                             "abstention_code": outcome.typed_abstention_code})

        if opts.generate_patches:
            patch = _outcome_to_patch(outcome)
            patches.append(patch)
            yield PipelineEvent("patch_ready", time.time(),
                                {"scan_id": sid,
                                 "finding_id": finding.finding_id,
                                 "file": str(source_path),
                                 "patch": patch.to_dict()})
            for gate in patch.gates:
                yield PipelineEvent("gate_result", time.time(),
                                    {"scan_id": sid,
                                     "finding_id": finding.finding_id,
                                     "file": str(source_path),
                                     "name": gate.name,
                                     "passed": gate.passed,
                                     "detail": gate.detail})

        yield PipelineEvent("file_finished", time.time(),
                            {"scan_id": sid,
                             "finding_id": finding.finding_id,
                             "file": str(source_path),
                             "had_finding": True})

    elapsed_ms = int((time.perf_counter() - started) * 1000)
    record = ScanRecord(sid, str(root_path), len(files_seen), finding_rows,
                        patches, elapsed_ms)
    yield PipelineEvent("scan_finished", time.time(),
                        {"scan_id": sid, "record": record.to_dict()})


# ---------------------------------------------------------------------------
# SARIF import
# ---------------------------------------------------------------------------


def import_sarif_bytes(
    blob: bytes, *, detector_hint: Literal["codeql", "semgrep", "sonarqube", "auto"] = "auto"
) -> list[FindingRecord]:
    """Parse a SARIF document into normalized :class:`FindingRecord` rows.

    ``detector_hint='auto'`` inspects ``runs[].tool.driver.name`` and
    dispatches to the matching adapter. Unknown drivers fall back to
    the CodeQL adapter, which is the most permissive.
    """
    if not blob:
        return []
    with tempfile.NamedTemporaryFile(
        "wb", suffix=".sarif", delete=False
    ) as fh:
        fh.write(blob)
        tmp_path = Path(fh.name)
    try:
        parsed = _detect_and_parse(tmp_path, detector_hint)
    finally:
        tmp_path.unlink(missing_ok=True)
    return [FindingRecord.from_irsam(f) for f in parsed]


def _detect_and_parse(
    path: Path, hint: str
) -> Iterable[IRSAMFinding]:
    if hint != "auto":
        return _dispatch(hint, path)
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return []
    for run in data.get("runs", []):
        name = (run.get("tool", {})
                   .get("driver", {})
                   .get("name", "")).lower()
        if "semgrep" in name:
            return _dispatch("semgrep", path)
        if "sonar" in name:
            return _dispatch("sonarqube", path)
        if "codeql" in name:
            return _dispatch("codeql", path)
    return _dispatch("codeql", path)


def _dispatch(name: str, path: Path) -> Iterable[IRSAMFinding]:
    if name == "semgrep":
        return list(_semgrep_adapter.adapt(path))
    if name == "sonarqube":
        return list(_sonarqube_adapter.adapt(path))
    return list(_codeql_adapter.adapt(path))
