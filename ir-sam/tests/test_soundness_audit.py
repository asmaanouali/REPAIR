"""Mechanized soundness-audit tests over the synthetic Juliet-mini corpus.

For every case the synthetic benchmark generates we run the full
pipeline; for each case that reaches stage G we exercise the audit
predicates from :mod:`core.iam.audit` and assert every predicate
passes. Failures cause the test to fail *and* dump a counterexample
file under ``reports/soundness/<run-id>/counterexamples/``.
"""

from __future__ import annotations

import os
import tempfile
from pathlib import Path

import pytest

from bench.juliet_mini import generate_benchmark
from core.binder.loader import load_catalog
from core.iam.audit import audit, write_report
from core.pipeline import run_file

pytestmark = pytest.mark.soundness


_REPORTS = Path(__file__).resolve().parent.parent / "reports" / "soundness" / "audit"


@pytest.fixture(scope="module")
def bench_cases() -> list[tuple[str, Path]]:
    tmp = Path(tempfile.mkdtemp(prefix="irsam-audit-"))
    cases = generate_benchmark(tmp, per_category=1)
    return [(c.name, tmp / f"{c.name}.java") for c in cases]


@pytest.fixture(scope="module")
def catalog():
    root = Path(__file__).resolve().parent.parent
    return load_catalog(root / "binders" / "sql_jdbc.yaml")


def test_audit_passes_on_every_stage_g_case(bench_cases, catalog) -> None:
    failures: list[tuple[str, str]] = []
    for case_id, java_path in bench_cases:
        outcome = run_file(java_path)
        if outcome.stage_reached != "G":
            continue
        assert outcome.iam is not None
        assert outcome.plan is not None
        assert outcome.patch is not None
        report = audit(
            case_id=case_id,
            iam=outcome.iam,
            realizations=outcome.plan.realizations,
            parameterizing_apis=set(catalog.parameterizing_apis),
            patched_source=outcome.patch.patched_source,
            language="java",
            oracle_outcomes=(),  # P4 is vacuously true without a live oracle
        )
        write_report(report, _REPORTS)
        if not report.overall_passed:
            failures.append((case_id, report.to_json()))
    assert not failures, (
        "soundness audit failed for cases:\n"
        + "\n".join(f"  - {cid}: {body}" for cid, body in failures)
    )
