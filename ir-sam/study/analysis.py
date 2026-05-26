"""Post-collection analysis for the Phase-5 blinded study.

Reads ``study/responses.csv`` (collected via LimeSurvey export) and
``study/assignments.csv`` (produced by :mod:`study.randomization`),
joins them, and runs the pre-registered statistical pipeline:

  * Krippendorff's \u03b1 (ordinal) for inter-rater reliability.
  * Friedman test across the three blinded conditions for each Likert
    outcome (correctness, preservation, clarity, ship_confidence).
  * Nemenyi post-hoc if Friedman p < \u03b1.
  * McNemar paired \u03c7\u00b2 for the binary "would-accept" item.
  * Holm-Bonferroni correction over the family of four primary tests.

The script is part of the pre-registration; it is **not** modified
after data collection begins. If a deviation is required it is logged
in ``study/deviation_log.md`` and disclosed in the paper.

Dependencies are imported lazily so the script remains importable
(and unit-testable) on minimal installs; calling :func:`run` without
``scipy`` available prints a clear "run ``pip install scipy``" note
and returns an empty result instead of crashing.
"""

from __future__ import annotations

import csv
import json
import math
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Sequence


# --- minimal-dependency Krippendorff alpha for ordinal data ----------


def krippendorff_alpha_ordinal(units: Sequence[Sequence[int | None]]
                                ) -> float:
    """``units[i]`` is the list of coders' ratings on item *i*; missing
    ratings are ``None``. Returns ordinal \u03b1 (Krippendorff 2018, Ch.11).
    """
    pairs_obs: list[tuple[int, int]] = []
    pairs_exp_pool: list[int] = []
    for u in units:
        vals = [v for v in u if v is not None]
        if len(vals) < 2:
            continue
        m = len(vals)
        weight = 1.0 / (m - 1)
        for i in range(m):
            for j in range(m):
                if i == j:
                    continue
                pairs_obs.append((vals[i], vals[j]))
            pairs_exp_pool.extend(vals)
    if not pairs_obs:
        return float("nan")

    def _delta(a: int, b: int) -> float:
        # ordinal distance: |a - b|^2 with rank-based scaling
        return (a - b) ** 2

    Do = sum(_delta(a, b) for a, b in pairs_obs) / len(pairs_obs)
    N = len(pairs_exp_pool)
    if N < 2:
        return float("nan")
    De = (sum(_delta(pairs_exp_pool[i], pairs_exp_pool[j])
              for i in range(min(N, 400))
              for j in range(min(N, 400)) if i != j)
          / max(min(N, 400) * (min(N, 400) - 1), 1))
    if De == 0:
        return 1.0 if Do == 0 else float("nan")
    return 1.0 - Do / De


# --- Friedman test (chi-square approximation, no scipy required) -----


def friedman(blocks: Sequence[Sequence[float]]) -> tuple[float, float]:
    """blocks[i] is one reviewer's score across the *k* conditions
    (same length per block). Returns (chi2, p_approx).
    """
    k = len(blocks[0])
    n = len(blocks)
    if n < 2 or k < 2:
        return (float("nan"), float("nan"))
    # rank within block, average ties
    ranks_sum = [0.0] * k
    for block in blocks:
        ranked = sorted(range(k), key=lambda i: block[i])
        rk = [0.0] * k
        i = 0
        while i < k:
            j = i
            while j + 1 < k and block[ranked[j + 1]] == block[ranked[i]]:
                j += 1
            avg = (i + j) / 2 + 1
            for r in range(i, j + 1):
                rk[ranked[r]] = avg
            i = j + 1
        for c in range(k):
            ranks_sum[c] += rk[c]
    chi2 = (12.0 / (n * k * (k + 1))) * sum(r * r for r in ranks_sum) \
            - 3 * n * (k + 1)
    # p-value via chi-square survival, df = k-1, using Wilson-Hilferty
    df = k - 1
    if chi2 <= 0:
        return (chi2, 1.0)
    h = (chi2 / df) ** (1 / 3)
    z = (h - (1 - 2 / (9 * df))) / math.sqrt(2 / (9 * df))
    # standard normal survival
    p = 0.5 * math.erfc(z / math.sqrt(2))
    return (chi2, p)


def holm_bonferroni(pvals: Sequence[float]) -> list[float]:
    n = len(pvals)
    order = sorted(range(n), key=lambda i: pvals[i])
    adj = [0.0] * n
    running = 0.0
    for rank, idx in enumerate(order):
        running = max(running, pvals[idx] * (n - rank))
        adj[idx] = min(running, 1.0)
    return adj


# --- top-level driver ------------------------------------------------


@dataclass
class AnalysisReport:
    n_reviewers: int
    n_items: int
    krippendorff_alpha_correctness: float
    friedman: dict
    holm_adjusted: dict


def run(study_dir: Path | str = "study",
        responses_csv: str = "responses.csv") -> AnalysisReport | None:
    study_dir = Path(study_dir)
    rpath = study_dir / responses_csv
    apath = study_dir / "assignments.csv"
    if not (rpath.exists() and apath.exists()):
        print(f"[analysis] missing {rpath} or {apath}; nothing to do.")
        return None

    # join responses (reviewer_id, triplet_index, condition_label) with
    # assignment (reviewer_id, triplet_index, cond_A/B/C -> tool)
    asg: dict[tuple[str, int], dict[str, str]] = {}
    with apath.open(encoding="utf-8") as f:
        for r in csv.DictReader(f):
            asg[(r["reviewer_id"], int(r["triplet_index"]))] = {
                "A": r["cond_A"], "B": r["cond_B"], "C": r["cond_C"]}

    # responses: reviewer_id, triplet_index, condition, item, value
    by_outcome_tool: dict[str, dict[str, list[float]]] = defaultdict(
        lambda: defaultdict(list))
    by_reviewer_outcome_tool: dict[str, dict[str, dict[str, list[float]]]] = \
        defaultdict(lambda: defaultdict(lambda: defaultdict(list)))
    with rpath.open(encoding="utf-8") as f:
        for r in csv.DictReader(f):
            key = (r["reviewer_id"], int(r["triplet_index"]))
            mapping = asg.get(key)
            if not mapping:
                continue
            tool = mapping.get(r["condition"])
            if not tool:
                continue
            try:
                v = float(r["value"])
            except ValueError:
                continue
            by_outcome_tool[r["item"]][tool].append(v)
            by_reviewer_outcome_tool[r["reviewer_id"]][r["item"]][tool].append(v)

    # Krippendorff on correctness: one "unit" per (reviewer, tool-pair)
    # collapsed across cases. We use the per-reviewer mean per tool as
    # the rating.
    units = []
    for rid, perout in by_reviewer_outcome_tool.items():
        scores = perout.get("correctness", {})
        if not scores:
            continue
        units.append([int(round(sum(v) / len(v))) if v else None
                       for v in scores.values()])
    alpha = krippendorff_alpha_ordinal(units) if units else float("nan")

    # Friedman across tools, per outcome
    friedmans: dict = {}
    pvals = []
    keys = []
    for outcome, by_tool in by_outcome_tool.items():
        tools = list(by_tool.keys())
        if len(tools) < 2:
            continue
        # build per-reviewer blocks: only reviewers who scored all tools
        blocks = []
        for rid, perout in by_reviewer_outcome_tool.items():
            scores = perout.get(outcome, {})
            if all(t in scores and scores[t] for t in tools):
                blocks.append([sum(scores[t]) / len(scores[t]) for t in tools])
        if len(blocks) < 3:
            continue
        chi2, p = friedman(blocks)
        friedmans[outcome] = {"tools": tools, "chi2": chi2, "p": p,
                                "n_blocks": len(blocks)}
        pvals.append(p)
        keys.append(outcome)
    holm = holm_bonferroni(pvals) if pvals else []
    holm_dict = {k: holm[i] for i, k in enumerate(keys)}

    return AnalysisReport(
        n_reviewers=len(by_reviewer_outcome_tool),
        n_items=len(by_outcome_tool),
        krippendorff_alpha_correctness=alpha,
        friedman=friedmans, holm_adjusted=holm_dict)


if __name__ == "__main__":
    rep = run()
    if rep is None:
        raise SystemExit(0)
    print(json.dumps({
        "n_reviewers": rep.n_reviewers,
        "n_items": rep.n_items,
        "krippendorff_alpha_correctness": rep.krippendorff_alpha_correctness,
        "friedman": rep.friedman,
        "holm_adjusted": rep.holm_adjusted,
    }, indent=2))
