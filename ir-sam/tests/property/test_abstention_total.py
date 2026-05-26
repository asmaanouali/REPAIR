"""Property: every input either yields a Patch or a *typed* abstention.

The IR-SAM pipeline must never raise an uncaught exception on any
input: every failure mode is supposed to map to a typed `⊥` value
recorded as ``PipelineOutcome.abstention_reason``. This is the
totality property from docs/formal-model.md §6.

We fuzz the pipeline with arbitrary Java-like inputs to surface
crashes. The inputs are *not* required to be valid Java; valid
abstentions are pass results, not failures.
"""

from __future__ import annotations

import tempfile
from pathlib import Path

import hypothesis.strategies as st
import pytest
from hypothesis import HealthCheck, given, settings

import core.pipeline as _pipeline_mod
from core.pipeline import PipelineOutcome, run_file
from core.validator import GateOutcome, GateReport

pytestmark = pytest.mark.property


_VALID_STAGES = {"A", "B", "C", "D", "E", "F", "G"}


def _stub_gates(*, file: str, patched_source: str, **_: object) -> GateReport:
    """Replace Stage G with a no-op so we don't shell out to ``javac`` for
    every Hypothesis example. The totality property is about the
    orchestrator never raising, not about gate behaviour, which is
    covered by ``tests/test_validator_gates.py``.
    """
    g = GateOutcome("stub", True, "stubbed in totality property test")
    return GateReport(file=file, gates=(g,), overall_passed=True)


@pytest.fixture(autouse=True)
def _no_subprocess_gates(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(_pipeline_mod, "run_all_gates", _stub_gates)


@given(
    body=st.text(
        alphabet=st.characters(min_codepoint=32, max_codepoint=126,
                               blacklist_characters="\x00"),
        min_size=0,
        max_size=512,
    ),
)
@settings(
    max_examples=75,
    deadline=None,
    suppress_health_check=[HealthCheck.too_slow, HealthCheck.function_scoped_fixture],
)
def test_pipeline_total_on_arbitrary_java_like_input(body: str) -> None:
    """No uncaught exceptions; always a PipelineOutcome with a known stage."""
    src = (
        "import java.sql.*;\n"
        "public class Probe {\n"
        "  void run(Connection c, String x) throws Exception {\n"
        f"    Statement s = c.createStatement();\n"
        f"    s.executeQuery(\"SELECT * FROM t WHERE id = '\" + x + \"'\");\n"
        f"    // {body}\n"
        "  }\n"
        "}\n"
    )
    with tempfile.TemporaryDirectory() as tmp:
        p = Path(tmp) / "Probe.java"
        p.write_text(src, encoding="utf-8")
        out = run_file(p)
    assert isinstance(out, PipelineOutcome)
    assert out.stage_reached in _VALID_STAGES
    if out.patch is None:
        assert out.abstention_reason, (
            "non-patched outcome must carry a typed abstention reason"
        )
