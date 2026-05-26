"""Unit tests for :mod:`eval.stats`.

These tests check the math against fixtures with known answers and do
*not* require scipy unless the paired Wilcoxon path is exercised (the
import is guarded so the bootstrap tests pass on the minimal install).
"""

from __future__ import annotations

import pytest

from eval.metrics import CaseObservation
from eval.stats import _bootstrap_ci, tool_stats

pytestmark = pytest.mark.unit


def _mkobs(tool: str, case_id: str, *, applied: bool = True,
           functional_pass: bool = True,
           benign_equivalent: bool = True,
           latency: float = 0.1,
           abstained: bool = False,
           irreparable: bool = False) -> CaseObservation:
    return CaseObservation(
        case_id=case_id,
        tool=tool,
        applied=applied,
        functional_pass=functional_pass,
        benign_equivalent=benign_equivalent,
        residual_cwe_count=0,
        latency_seconds=latency,
        abstained=abstained,
        ground_truth_irreparable=irreparable,
    )


def test_bootstrap_ci_brackets_point_estimate() -> None:
    obs = [_mkobs("T", f"c{i}", functional_pass=(i % 2 == 0)) for i in range(20)]
    from eval.metrics import m2_functional_fix_rate
    point, lo, hi = _bootstrap_ci(obs, m2_functional_fix_rate,
                                  iterations=500, rng_seed=42)
    assert 0.0 <= lo <= point <= hi <= 1.0
    # Expected M2 ≈ 0.5
    assert 0.2 <= point <= 0.8


def test_bootstrap_ci_empty_obs_returns_zero() -> None:
    from eval.metrics import m1_patch_applicability
    assert _bootstrap_ci([], m1_patch_applicability) == (0.0, 0.0, 0.0)


def test_tool_stats_emits_all_six_metrics() -> None:
    obs = [_mkobs("IR-SAM", f"c{i}") for i in range(10)]
    s = tool_stats(obs, iterations=200)
    assert s.tool == "IR-SAM"
    assert s.n == 10
    assert set(s.metrics) == {
        "M1_patch_applicability", "M2_functional_fix_rate",
        "M3_semantic_equivalence", "M4_residual_cwe_mean",
        "M5_median_latency_sec", "M6_abstention_precision",
    }
    for _, (point, lo, hi) in s.metrics.items():
        assert lo <= point <= hi
