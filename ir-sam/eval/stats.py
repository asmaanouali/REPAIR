"""Statistical helpers for the IR-SAM evaluation harness.

Produces:
- bootstrap 95% confidence intervals for M1..M6,
- paired Wilcoxon signed-rank tests of IR-SAM vs. each baseline on M2,
- Holm--Bonferroni family-wise error control across baselines.

``scipy`` is required (declared in the ``test-prod`` extra).
"""

from __future__ import annotations

import statistics
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from eval.metrics import (
    CaseObservation,
    m1_patch_applicability,
    m2_functional_fix_rate,
    m3_semantic_equivalence,
    m4_residual_cwe_density,
    m5_median_latency,
    m6_abstention_precision,
)

if TYPE_CHECKING:
    pass


# --- bootstrap CIs ----------------------------------------------------------


def _bootstrap_ci(
    obs: Sequence[CaseObservation],
    metric: Callable[[Sequence[CaseObservation]], float],
    *,
    iterations: int = 1000,
    confidence: float = 0.95,
    rng_seed: int = 20260524,
) -> tuple[float, float, float]:
    """Return (point_estimate, lower, upper) using simple resampling."""
    import random as _random
    rng = _random.Random(rng_seed)
    n = len(obs)
    if n == 0:
        return (0.0, 0.0, 0.0)
    point = metric(obs)
    samples: list[float] = []
    obs_list = list(obs)
    for _ in range(iterations):
        resample = [obs_list[rng.randrange(n)] for _ in range(n)]
        samples.append(metric(resample))
    samples.sort()
    alpha = (1.0 - confidence) / 2.0
    lo = samples[int(alpha * iterations)]
    hi = samples[min(iterations - 1, int((1 - alpha) * iterations))]
    return (point, lo, hi)


# --- per-tool ---------------------------------------------------------------


_METRICS = {
    "M1_patch_applicability":  m1_patch_applicability,
    "M2_functional_fix_rate":  m2_functional_fix_rate,
    "M3_semantic_equivalence": m3_semantic_equivalence,
    "M4_residual_cwe_mean":    m4_residual_cwe_density,
    "M5_median_latency_sec":   m5_median_latency,
    "M6_abstention_precision": m6_abstention_precision,
}


@dataclass
class ToolStats:
    tool: str
    n: int
    metrics: dict[str, tuple[float, float, float]] = field(default_factory=dict)

    def as_dict(self) -> dict:
        return {
            "tool": self.tool,
            "n": self.n,
            "metrics": {k: {"point": v[0], "ci_lo": v[1], "ci_hi": v[2]}
                        for k, v in self.metrics.items()},
        }


def tool_stats(obs: Sequence[CaseObservation],
               *,
               iterations: int = 1000,
               rng_seed: int = 20260524) -> ToolStats:
    if not obs:
        return ToolStats(tool="<empty>", n=0)
    tool = obs[0].tool
    res = ToolStats(tool=tool, n=len(obs))
    for name, fn in _METRICS.items():
        res.metrics[name] = _bootstrap_ci(obs, fn, iterations=iterations,
                                          rng_seed=rng_seed)
    return res


# --- paired Wilcoxon + Holm--Bonferroni -------------------------------------


@dataclass
class PairedTest:
    treatment: str
    baseline: str
    metric: str
    n_pairs: int
    statistic: float
    p_value: float
    adjusted_p: float | None = None
    rejected: bool = False


def _paired_vector(
    treatment_obs: Sequence[CaseObservation],
    baseline_obs: Sequence[CaseObservation],
    project: Callable[[CaseObservation], float],
) -> tuple[list[float], list[float]]:
    by_case_t = {o.case_id: o for o in treatment_obs}
    by_case_b = {o.case_id: o for o in baseline_obs}
    shared = sorted(set(by_case_t) & set(by_case_b))
    ts = [project(by_case_t[c]) for c in shared]
    bs = [project(by_case_b[c]) for c in shared]
    return ts, bs


def paired_wilcoxon_vs_baselines(
    treatment_obs: Sequence[CaseObservation],
    baselines: dict[str, Sequence[CaseObservation]],
    *,
    metric: str = "M2_functional_fix_rate",
) -> list[PairedTest]:
    """Run paired Wilcoxon of treatment vs. each baseline on the chosen metric,
    then apply Holm--Bonferroni correction across baselines.
    """
    from scipy.stats import wilcoxon  # type: ignore[import-untyped]

    def _project(o: CaseObservation) -> float:
        if metric == "M2_functional_fix_rate":
            return 1.0 if (o.applied and o.functional_pass) else 0.0
        if metric == "M1_patch_applicability":
            return 1.0 if o.applied else 0.0
        if metric == "M3_semantic_equivalence":
            return 1.0 if (o.applied and o.benign_equivalent) else 0.0
        if metric == "M4_residual_cwe_mean":
            return float(o.residual_cwe_count) if o.applied else 0.0
        if metric == "M5_median_latency_sec":
            return float(o.latency_seconds)
        if metric == "M6_abstention_precision":
            return 1.0 if (o.abstained and o.ground_truth_irreparable) else 0.0
        raise ValueError(f"unknown metric: {metric!r}")

    tests: list[PairedTest] = []
    treatment_tool = treatment_obs[0].tool if treatment_obs else "treatment"
    for name, b_obs in baselines.items():
        ts, bs = _paired_vector(treatment_obs, b_obs, _project)
        if not ts or all(t == b for t, b in zip(ts, bs)):
            tests.append(PairedTest(treatment_tool, name, metric, len(ts),
                                    statistic=0.0, p_value=1.0))
            continue
        try:
            stat, p = wilcoxon(ts, bs, zero_method="wilcox",
                               alternative="greater")
        except ValueError:
            stat, p = 0.0, 1.0
        tests.append(PairedTest(treatment_tool, name, metric, len(ts),
                                statistic=float(stat), p_value=float(p)))

    # Holm--Bonferroni
    indexed = sorted(enumerate(tests), key=lambda kv: kv[1].p_value)
    k = len(indexed)
    for rank, (_, t) in enumerate(indexed):
        t.adjusted_p = min(1.0, t.p_value * (k - rank))
        t.rejected = t.adjusted_p < 0.05
    # enforce monotonicity (Holm step-up)
    prev = 0.0
    for _, t in indexed:
        assert t.adjusted_p is not None
        if t.adjusted_p < prev:
            t.adjusted_p = prev
        prev = t.adjusted_p
    return tests


# --- top-level dump ---------------------------------------------------------


def summarize(
    by_tool: dict[str, Sequence[CaseObservation]],
    *,
    treatment: str = "IR-SAM",
    iterations: int = 1000,
) -> dict:
    stats = {name: tool_stats(obs, iterations=iterations).as_dict()
             for name, obs in by_tool.items()}
    baselines = {n: o for n, o in by_tool.items() if n != treatment}
    paired = []
    if treatment in by_tool and baselines:
        for t in paired_wilcoxon_vs_baselines(by_tool[treatment], baselines):
            paired.append({
                "treatment": t.treatment,
                "baseline": t.baseline,
                "metric": t.metric,
                "n_pairs": t.n_pairs,
                "statistic": t.statistic,
                "p_value": t.p_value,
                "adjusted_p": t.adjusted_p,
                "rejected": t.rejected,
            })
    return {"per_tool": stats, "paired_tests_M2": paired}
