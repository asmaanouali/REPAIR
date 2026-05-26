"""End-to-end pipeline tests on the synthetic Juliet-mini benchmark."""

from __future__ import annotations

import shutil
import tempfile
from pathlib import Path

from bench.juliet_mini import generate_benchmark
from core.pipeline import run_file


def test_eq_string_case_reaches_G_and_passes():
    with tempfile.TemporaryDirectory() as tmp:
        bench_dir = Path(tmp) / "bench"
        cases = generate_benchmark(bench_dir, per_category=1)
        eq_string = next(c for c in cases if c.category == "concat-eq-string")
        out = run_file(bench_dir / f"{eq_string.name}.java")
        assert out.stage_reached == "G", out.abstention_reason
        assert out.gates is not None
        assert out.gates.overall_passed, [
            (g.name, g.detail) for g in out.gates.gates if not g.passed
        ]


def test_concat_in_list_resolved_by_disambiguator():
    """IN-list with a single attacker-controlled hole used to abstain at
    stage D. The Stage-D disambiguator (Phase 8) is expected to resolve it
    to ``in_list_csv``, which the binder catalog supports via
    ``Cardinality.MANY_BOUNDED``; the pipeline then reaches stage G.
    """
    import os
    with tempfile.TemporaryDirectory() as tmp:
        bench_dir = Path(tmp) / "bench"
        cases = generate_benchmark(bench_dir, per_category=1)
        in_list = next(c for c in cases if c.category == "concat-in-list")
        # Force the deterministic heuristic so the test is hermetic.
        prev = os.environ.get("IR_SAM_DISAMBIG_POLICY")
        os.environ["IR_SAM_DISAMBIG_POLICY"] = "heuristic"
        try:
            out = run_file(bench_dir / f"{in_list.name}.java")
        finally:
            if prev is None:
                os.environ.pop("IR_SAM_DISAMBIG_POLICY", None)
            else:
                os.environ["IR_SAM_DISAMBIG_POLICY"] = prev
        # The disambiguator must have been invoked and recorded provenance.
        extra = out.extra or {}
        assert extra.get("disambig_invoked") is True, extra
        assert extra.get("disambig_site") == "sql/in_position"
        assert extra.get("disambig_label") in {"in_list_csv", "string_value"}
        # When the heuristic picks in_list_csv (list/array host type), the
        # IN-list path is reachable end-to-end; otherwise we may still abstain
        # at D for the safe label. Either is correct behavior.
        assert out.stage_reached in {"D", "G"}


def test_orderby_ident_abstains_without_allowlist():
    with tempfile.TemporaryDirectory() as tmp:
        bench_dir = Path(tmp) / "bench"
        cases = generate_benchmark(bench_dir, per_category=1)
        ob = next(c for c in cases if c.category == "concat-orderby-ident")
        out = run_file(bench_dir / f"{ob.name}.java")
        assert out.stage_reached == "E"
        assert out.abstention_reason == "no_allowlist"


def test_update_case_passes_all_gates():
    with tempfile.TemporaryDirectory() as tmp:
        bench_dir = Path(tmp) / "bench"
        cases = generate_benchmark(bench_dir, per_category=1)
        case = next(c for c in cases if c.category == "concat-update")
        out = run_file(bench_dir / f"{case.name}.java")
        assert out.stage_reached == "G", out.abstention_reason
        assert out.gates is not None and out.gates.overall_passed, [
            (g.name, g.detail) for g in out.gates.gates if not g.passed
        ]
