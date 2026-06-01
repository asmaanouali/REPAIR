"""End-to-end pipeline orchestrator: A -> B -> C -> D -> E -> F -> G."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from core.artifacts import PipelineJob, abstention_code_from_reason
from core.binder.loader import BinderCatalog, load_catalog
from core.disambig import Question, load_default_policy
from core.disambig import labels as disambig_labels
from core.ingest.unified import IRSAMFinding
from core.iam import IAM, SymbolEntry
from core.parsers import (
    SIGLift,
    SQL0AmbiguousIntent,
    SQL0SyntaxError,
    parse_template_to_sig,
)
from core.phi import PatchPlan, PhiAbstention, apply_phi, build_iam_from_lift
from core.pipeline.dispatch import LanguageBackend, get_backend
from core.recon import ParameterizedTemplate, ReconAbstention, reconstruct
from core.rewriter import PatchResult, RewriteAbstention, synthesize_patch
from core.slicer import (
    SliceAbstention,
    SliceResult,
    find_sink_calls,
    slice_sink_argument,
)
from core.slicer.project import ProjectModel
from core.validator import GateReport, run_all_gates


# --- output ------------------------------------------------------------------


@dataclass(frozen=True)
class PipelineOutcome:
    file: str
    sink_line: int | None
    stage_reached: str  # "A".."G"
    abstention_reason: str | None
    slice_result: SliceResult | None = None
    template: ParameterizedTemplate | None = None
    lift: SIGLift | None = None
    plan: PatchPlan | None = None
    patch: PatchResult | None = None
    gates: GateReport | None = None
    iam: IAM | None = None
    extra: dict[str, Any] = field(default_factory=dict)

    @property
    def patched(self) -> bool:
        return self.patch is not None

    @property
    def all_gates_passed(self) -> bool:
        return self.gates is not None and self.gates.overall_passed

    @property
    def typed_abstention_code(self) -> str | None:
        code = abstention_code_from_reason(self.stage_reached, self.abstention_reason)
        return code.value if code is not None else None


# --- main ---


_SUFFIX_TO_BACKEND_KEY: dict[str, tuple[str, str]] = {
    ".java": ("java", "sql"),
    ".py":   ("python", "sql"),
}


def run_file(
    java_path: Path | str,
    *,
    catalog_path: Path | str | None = None,
    allowlists: dict[str, str] | None = None,
    extra_symbols: tuple[SymbolEntry, ...] = (),
    project: "ProjectModel | None" = None,
) -> PipelineOutcome:
    """Run stages A..G for the first sink in ``java_path``.

    Returns a :class:`PipelineOutcome` annotated with the stage at
    which the pipeline either succeeded or abstained.

    The path's suffix selects the language backend (``.java`` →
    ``(java, sql)``; ``.py`` → ``(python, sql)``). Both the sink
    locator and the slicer come from that backend, so a Python
    snippet is no longer scanned with the Java regex.
    """
    path = Path(java_path)
    src = path.read_text(encoding="utf-8")

    # Stage A: pick the language backend by file extension. Default to
    # the Java/SQL backend for unknown suffixes so legacy callers keep
    # working.
    key = _SUFFIX_TO_BACKEND_KEY.get(path.suffix.lower(), ("java", "sql"))
    backend = get_backend(*key)
    if backend is None:
        return PipelineOutcome(
            str(path), None, "A",
            f"unsupported_backend:{key[0]}/{key[1]}",
        )

    sinks = backend.find_sinks(src)
    if not sinks:
        return PipelineOutcome(str(path), None, "A", "no_sink_found")
    sink_line = sinks[0][0]

    return _run_source_at_sink(
        path,
        src,
        sink_line,
        catalog_path=catalog_path,
        allowlists=allowlists,
        extra_symbols=extra_symbols,
        backend=backend,
        project=project,
    )


def run_finding(
    project_root: Path | str,
    finding: IRSAMFinding,
    *,
    catalog_path: Path | str | None = None,
    allowlists: dict[str, str] | None = None,
    extra_symbols: tuple[SymbolEntry, ...] = (),
    project: "ProjectModel | None" = None,
) -> PipelineOutcome:
    """Run stages A..G for one normalized detector finding.

    The (language, interpreter) tuple selects a registered
    :class:`~core.pipeline.dispatch.LanguageBackend`. If no backend is
    registered for the tuple, the pipeline returns a typed
    ``unsupported_backend`` abstention at stage A.
    """
    job = PipelineJob.from_finding(project_root, finding)
    extra = job.to_metadata()
    path = Path(job.source_path)
    sink_line = finding.location.line_start

    backend = get_backend(finding.language, finding.interpreter)
    if backend is None:
        return PipelineOutcome(
            str(path), sink_line, "A",
            f"unsupported_backend:{finding.language}/{finding.interpreter}",
            extra=extra,
        )

    if not path.exists():
        return PipelineOutcome(
            str(path), sink_line, "A", "finding_file_not_found",
            extra=extra,
        )

    try:
        src = path.read_text(encoding="utf-8")
    except OSError as exc:
        return PipelineOutcome(
            str(path), sink_line, "A", f"finding_file_unreadable:{exc}",
            extra=extra,
        )

    return _run_source_at_sink(
        path,
        src,
        sink_line,
        catalog_path=catalog_path,
        allowlists=allowlists,
        extra_symbols=extra_symbols,
        extra=extra,
        backend=backend,
        project=project,
    )


def _slice_stage_b(
    path: Path,
    src: str,
    sink_line: int,
    backend: LanguageBackend | None,
    project: "ProjectModel | None",
) -> SliceResult | SliceAbstention:
    """Stage B dispatch: global SDG slice when enabled, else local slice.

    The global slicer is used for Java sources when either an explicit
    :class:`ProjectModel` is supplied or ``IRSAM_SLICER=sdg`` is set.
    A model is built lazily from the sink file's directory when none is
    given. Default behaviour (no flag, no project) is unchanged.
    """
    import os

    engine = os.environ.get("IRSAM_SLICER", "regex").strip().lower()
    is_java = path.suffix.lower() == ".java"
    if is_java and (engine == "sdg" or project is not None):
        from core.framework import extract_facts
        from core.slicer.sdg import slice_global

        model = project
        if model is None:
            model = ProjectModel.from_root(path.parent)
        if path not in model.files:
            model.files[path] = src
            model._index_source(path, src)
        facts = extract_facts(host_language="java", source=src)
        return slice_global(
            model, path, sink_line, tainted_params=facts.tainted_params)

    if backend is not None:
        return backend.slice_at_sink(src, sink_line)
    return slice_sink_argument(src, sink_line)


def _run_source_at_sink(
    path: Path,
    src: str,
    sink_line: int,
    *,
    catalog_path: Path | str | None,
    allowlists: dict[str, str] | None,
    extra_symbols: tuple[SymbolEntry, ...],
    extra: dict[str, Any] | None = None,
    backend: LanguageBackend | None = None,
    project: "ProjectModel | None" = None,
) -> PipelineOutcome:
    base_extra = dict(extra or {})

    # Stage B -- global (SDG) slice when enabled, else per-backend local slice.
    slice_ = _slice_stage_b(path, src, sink_line, backend, project)
    if isinstance(slice_, SliceAbstention):
        return PipelineOutcome(str(path), sink_line, "B", slice_.reason,
                               extra=base_extra)

    # Stage C
    template = reconstruct(slice_)
    if isinstance(template, ReconAbstention):
        return PipelineOutcome(str(path), sink_line, "C", template.reason,
                               slice_result=slice_, extra=base_extra)

    # Stage D
    disambig_extra: dict[str, Any] = {}
    try:
        lift = parse_template_to_sig(template)
    except SQL0AmbiguousIntent as e:
        # Stage-D ambiguous intent: call the (heuristic-or-model) disambiguator
        # before giving up. The disambiguator picks one label from a finite,
        # syntactically-safe label set; the parser is re-invoked with the
        # resulting hint. If parsing still fails, we surface the original
        # abstention but annotate the outcome with the disambiguator's
        # decision for provenance.
        disambig_extra = _try_disambiguate_sql_in(template)
        hints = disambig_extra.get("disambig_hints") or {}
        if hints:
            try:
                lift = parse_template_to_sig(template, disambig_hints=hints)
            except (SQL0AmbiguousIntent, SQL0SyntaxError) as e2:
                return PipelineOutcome(
                    str(path), sink_line, "D",
                    f"ambiguous_intent_after_disambig:{e2}",
                    slice_result=slice_, template=template,
                    extra=_merge_extra(base_extra, disambig_extra),
                )
        else:
            return PipelineOutcome(
                str(path), sink_line, "D",
                f"ambiguous_intent:{e}",
                slice_result=slice_, template=template,
                extra=_merge_extra(base_extra, disambig_extra),
            )
    except SQL0SyntaxError as e:
        return PipelineOutcome(str(path), sink_line, "D",
                               f"sql0_syntax:{e}",
                               slice_result=slice_, template=template,
                               extra=base_extra)

    # Build IAM + host_exprs map (hole names "h0","h1",... aligned with marker idx)
    host_exprs = {f"h{th.idx}": th.host_expr for th in template.holes}
    iam = build_iam_from_lift(lift, host_exprs, symbols=extra_symbols)

    # Stage E
    if catalog_path is not None:
        cat_path = Path(catalog_path)
    elif backend is not None:
        cat_path = backend.default_catalog_yaml
    else:
        cat_path = (Path(__file__).resolve().parents[2]
                    / "binders" / "sql_jdbc.yaml")
    catalog: BinderCatalog = load_catalog(cat_path)
    plan = apply_phi(lift.sig, lift.holes, host_exprs, catalog,
                     allowlists=allowlists)
    if isinstance(plan, PhiAbstention):
        return PipelineOutcome(str(path), sink_line, "E", plan.reason,
                               slice_result=slice_, template=template, lift=lift,
                               iam=iam,
                               extra=_merge_extra(base_extra, disambig_extra))

    # Stage F
    synth = backend.synthesize_patch if backend is not None else synthesize_patch
    try:
        patch = synth(src, slice_, plan)
    except RewriteAbstention as e:
        return PipelineOutcome(str(path), sink_line, "F", str(e),
                               slice_result=slice_, template=template, lift=lift,
                               plan=plan, iam=iam,
                               extra=_merge_extra(base_extra, disambig_extra))

    # Stage G
    original_concat, patched_oracle, param_kind = _build_oracle_templates(template, lift)
    gates = run_all_gates(
        file=str(path),
        patched_source=patch.patched_source,
        iam=iam,
        realizations=plan.realizations,
        parameterizing_apis=set(catalog.parameterizing_apis),
        original_concat_template=original_concat,
        patched_prepared_template=patched_oracle,
        param_kind=param_kind,
        language=backend.language if backend is not None else "java",
    )

    # Phase 9: collect proof obligations from the binders this patch
    # actually used so the facade can compute proof_status.
    proof_obligations: list[str] = []
    for bid in plan.binder_ids_used:
        try:
            obligation = catalog.find(bid).proof_obligation
        except KeyError:
            continue
        if obligation:
            proof_obligations.append(obligation)
    honesty_extra: dict[str, Any] = {
        "proof_obligations": tuple(proof_obligations),
    }

    return PipelineOutcome(
        file=str(path),
        sink_line=sink_line,
        stage_reached="G",
        abstention_reason=None,
        slice_result=slice_, template=template, lift=lift,
        plan=plan, patch=patch, gates=gates, iam=iam,
        extra=_merge_extra(base_extra, disambig_extra, honesty_extra),
    )


def _merge_extra(*parts: dict[str, Any]) -> dict[str, Any]:
    merged: dict[str, Any] = {}
    for part in parts:
        merged.update(part)
    return merged


def _build_oracle_templates(template: ParameterizedTemplate, lift: SIGLift
                            ) -> tuple[str, str, str]:
    """Translate the parameterized template into (orig-concat, patched, param-kind).

    For the differential gate we expose exactly *one* parameter slot:
    the first textual hole. The remaining holes are filled with benign
    constant defaults (``0`` for ints, ``'x'`` for strings) in both the
    original and patched oracle templates so SQLite can execute them.

    Returns:
        original_concat: ``... = '{p}'`` style for the attacker
            substitution; uses Python ``str.format(p=...)``.
        patched: ``... = ?`` parameterized form with one ``?``.
        param_kind: ``"integer"`` or ``"string"``.
    """
    text = template.text
    marker_re = re.compile(r"<<H(\d+)>>")
    indices = [int(m.group(1)) for m in marker_re.finditer(text)]
    if not indices:
        return text, text, "string"
    first = indices[0]
    sem = template.holes[first].sem
    param_kind = "integer" if sem == "integer" else "string"
    quote = "" if param_kind == "integer" else "'"

    def _benign(idx: int) -> str:
        s = template.holes[idx].sem
        return "0" if s == "integer" else "'x'"

    def _render(slot_for_first: str) -> str:
        seen = {"done": False}

        def sub(m: re.Match[str]) -> str:
            i = int(m.group(1))
            if i == first and not seen["done"]:
                seen["done"] = True
                return slot_for_first
            return _benign(i)
        return marker_re.sub(sub, s)

    s = text
    orig = _render(f"{quote}{{p}}{quote}")
    patched = _render("?")
    return orig, patched, param_kind


# --- disambiguation --------------------------------------------------------


def _try_disambiguate_sql_in(template: ParameterizedTemplate) -> dict[str, Any]:
    """Invoke the Stage-D disambiguator for an SQL IN-list ambiguity.

    Returns a provenance dict suitable for :attr:`PipelineOutcome.extra`:

    * ``disambig_invoked``: ``True``
    * ``disambig_site``: ``"sql/in_position"``
    * ``disambig_policy``: policy class name
    * ``disambig_label``: the chosen label
    * ``disambig_confidence``: 0..1
    * ``disambig_source``: ``Answer.source``
    * ``disambig_rationale``: ``Answer.rationale``
    * ``disambig_hints``: ``{hole_name -> label}`` ready for parser re-entry.
      Empty if the chosen label maps to no hint (i.e. preserve abstention).

    On any exception the function degrades to ``{}`` so the pipeline
    falls back to the original abstention path.
    """
    try:
        ls = disambig_labels.SQL_IN_POSITION
        # Build a host-type context string for the heuristic policy.
        type_tags = " ".join(
            (h.sem or "") for h in template.holes
        )
        question = Question(
            sig_text=template.text,
            context=f"interpreter=sql site=in_position holes={type_tags}",
            labels=ls.labels,
            interpreter="sql",
            site="in_position",
        )
        policy = load_default_policy()
        answer = policy.choose(question)
        # Find which hole the IN-list ambiguity attaches to. Without a
        # precise location pointer we conservatively apply the hint to
        # every hole; the parser only consults hints at IN-list sites,
        # so the broad mapping is safe.
        hints = {f"h{h.idx}": answer.label for h in template.holes}
        return {
            "disambig_invoked": True,
            "disambig_site": "sql/in_position",
            "disambig_policy": type(policy).__name__,
            "disambig_label": answer.label,
            "disambig_confidence": answer.confidence,
            "disambig_source": answer.source,
            "disambig_rationale": answer.rationale,
            "disambig_hints": hints,
        }
    except Exception as e:  # pragma: no cover - belt-and-braces
        return {
            "disambig_invoked": True,
            "disambig_site": "sql/in_position",
            "disambig_error": f"{type(e).__name__}: {e}",
            "disambig_hints": {},
        }
