"""Phase-5 master evaluator.

Loads the evaluable subset, runs every Phase-5 baseline on every case,
computes the six metrics (per-tool + aggregate), and emits:

  * ``reports/phase5_observations.csv``  -- per (tool, case) row
  * ``reports/phase5_metrics.json``       -- six metrics per tool
  * ``reports/phase5_failure_modes.json`` -- top-10 catalog
  * ``reports/phase5_failure_modes.md``
  * ``reports/phase5_summary.txt``        -- human-readable verdict

Acceptance rule (gating):

    PASS iff   M2(IR-SAM) - max_{b != IR-SAM} M2(b) >= 0.05  AND
               M4(IR-SAM) <= min_{b != IR-SAM} M4(b)         AND
               M6(IR-SAM) >= 0.80
"""

from __future__ import annotations

import argparse
import csv
import json
import re
import sys
from pathlib import Path

from bench.eval_corpus import EvalCase, corpus_stats, load_evaluable_subset
from baselines import ALL_BASELINES, BaselineResult
from eval.failure_modes import build_catalog, write_catalog
from eval.metrics import (
    CaseObservation, Stopwatch, benign_equivalent_text,
    residual_cwe_count, six_metrics,
)


def _ground_truth_irreparable(case: EvalCase) -> bool:
    """A case is irreparable by a single-file, single-statement rewrite
    if the maintainer fix changes the function signature or imports a
    new API surface. Heuristic: a 30%+ change in identifier set or a
    parameter-list arity change between pre and post.
    """
    if not case.post_path:
        return False
    import re as _re
    pre = case.pre_path.read_text(encoding="utf-8")
    post = case.post_path.read_text(encoding="utf-8")
    id_pre = set(_re.findall(r"[A-Za-z_]\w*", pre))
    id_post = set(_re.findall(r"[A-Za-z_]\w*", post))
    delta = len(id_pre ^ id_post) / max(len(id_pre | id_post), 1)
    return delta >= 0.30


def _observe(tool: str, case: EvalCase, res: BaselineResult,
             elapsed_s: float) -> CaseObservation:
    """Convert a :class:`BaselineResult` + ground-truth into a
    :class:`CaseObservation` consumable by the metrics module."""
    gt = case.post_path.read_text(encoding="utf-8") if case.post_path else ""
    patched_src = res.patched_source or ""
    functional = bool(res.applied and gt and benign_equivalent_text(
        patched_src, gt, jaccard_threshold=0.55))
    benign_eq = functional        # text-jaccard surrogate (oracle off here)
    residual = (residual_cwe_count(patched_src, case.language)
                if res.applied else 0)
    return CaseObservation(
        case_id=case.case_id, tool=tool, applied=res.applied,
        functional_pass=functional, benign_equivalent=benign_eq,
        residual_cwe_count=residual, latency_seconds=elapsed_s,
        abstained=res.abstained,
        ground_truth_irreparable=_ground_truth_irreparable(case),
        notes=res.notes)


def run_eval(datasets: tuple[str, ...] | None, out_dir: Path
             ) -> tuple[dict, list[dict]]:
    out_dir.mkdir(parents=True, exist_ok=True)
    cases = load_evaluable_subset(datasets=datasets)
    stats = corpus_stats(cases)
    records: list[dict] = []

    metrics_by_tool: dict[str, dict] = {}
    for bl in ALL_BASELINES:
        obs_list: list[CaseObservation] = []
        for case in cases:
            with Stopwatch() as sw:
                try:
                    res = bl.run(case)
                except Exception as e:
                    res = BaselineResult(
                        bl.name, "real", False, None, True,
                        f"adapter_exc:{type(e).__name__}:{str(e)[:80]}")
            o = _observe(bl.name, case, res, sw.elapsed)
            obs_list.append(o)
            records.append({
                "tool": bl.name, "tier": res.tier, "case_id": case.case_id,
                "cwe": case.cwe, "language": case.language,
                "interpreter": case.interpreter,
                "applied": o.applied, "functional_pass": o.functional_pass,
                "benign_equivalent": o.benign_equivalent,
                "residual_cwe_count": o.residual_cwe_count,
                "latency_seconds": round(o.latency_seconds, 4),
                "abstained": o.abstained, "notes": o.notes,
            })
        metrics_by_tool[bl.name] = six_metrics(obs_list)

    # write artifacts
    obs_csv = out_dir / "phase5_observations.csv"
    with obs_csv.open("w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(records[0].keys()))
        w.writeheader()
        for row in records:
            w.writerow(row)

    metrics_path = out_dir / "phase5_metrics.json"
    metrics_path.write_text(json.dumps(
        {"corpus": stats, "metrics_by_tool": metrics_by_tool},
        indent=2), encoding="utf-8")

    # top-10 catalog (only on non-IR-SAM cases vs. only IR-SAM? - we
    # include all tools so reviewers see comparative weakness rates)
    catalog = build_catalog(records, top_k=10)
    write_catalog(catalog, out_dir)

    # verdict
    verdict = _judge(metrics_by_tool)
    summary = _format_summary(stats, metrics_by_tool, verdict)
    (out_dir / "phase5_summary.txt").write_text(summary, encoding="utf-8")
    print(summary)
    return ({"corpus": stats, "metrics_by_tool": metrics_by_tool,
             "verdict": verdict}, records)


def _judge(metrics_by_tool: dict) -> dict:
    if "IR-SAM" not in metrics_by_tool:
        return {"pass": False, "reason": "IR-SAM not run"}
    ours = metrics_by_tool["IR-SAM"]
    others = {k: v for k, v in metrics_by_tool.items() if k != "IR-SAM"}
    if not others:
        return {"pass": False, "reason": "no baselines available"}
    best_other_m2 = max(v["M2_functional_fix_rate"] for v in others.values())
    min_other_m4 = min(v["M4_residual_cwe_mean"] for v in others.values())
    cond1 = ours["M2_functional_fix_rate"] - best_other_m2 >= 0.05
    cond2 = ours["M4_residual_cwe_mean"] <= min_other_m4
    cond3 = ours["M6_abstention_precision"] >= 0.80
    return {
        "pass": cond1 and cond2 and cond3,
        "m2_margin":   round(ours["M2_functional_fix_rate"] - best_other_m2, 4),
        "m4_diff":     round(ours["M4_residual_cwe_mean"] - min_other_m4, 4),
        "m6_value":    ours["M6_abstention_precision"],
        "cond_m2_margin_ge_0.05": cond1,
        "cond_m4_no_worse":        cond2,
        "cond_m6_ge_0.80":         cond3,
    }


def _format_summary(stats: dict, metrics_by_tool: dict, verdict: dict) -> str:
    lines = [
        "=" * 64,
        "IR-SAM Phase 5 -- large-scale evaluation",
        "=" * 64,
        "",
        f"corpus_source = {stats['corpus_source']}",
        f"n_cases       = {stats['total']}",
        f"by_dataset    = {stats['by_dataset']}",
        f"by_cwe        = {stats['by_cwe']}",
        f"by_language   = {stats['by_language']}",
        f"by_interpreter= {stats['by_interpreter']}",
        "",
        "six metrics (per tool):",
        f"  {'tool':18s}  {'M1':>6s} {'M2':>6s} {'M3':>6s} {'M4':>6s} "
        f"{'M5(s)':>7s} {'M6':>6s}  n",
    ]
    for tool, m in metrics_by_tool.items():
        lines.append(
            f"  {tool:18s}  "
            f"{m['M1_patch_applicability']:>6.3f} "
            f"{m['M2_functional_fix_rate']:>6.3f} "
            f"{m['M3_semantic_equivalence']:>6.3f} "
            f"{m['M4_residual_cwe_mean']:>6.3f} "
            f"{m['M5_median_latency_sec']:>7.3f} "
            f"{m['M6_abstention_precision']:>6.3f}  "
            f"{m['n_observations']}")
    lines += ["", "VERDICT: " + ("PASS" if verdict.get("pass") else "FAIL"),
              json.dumps(verdict, indent=2), ""]
    return "\n".join(lines)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--dataset",
                    choices=["cvefixes", "vul4j", "bigvul", "synth", "all"],
                    default="all")
    ap.add_argument("--out", default="reports")
    args = ap.parse_args(argv)
    datasets = (None if args.dataset == "all"
                else (args.dataset,)) if args.dataset != "synth" else ("synth",)
    res, _ = run_eval(datasets, Path(args.out))
    return 0 if res["verdict"].get("pass") else 1


if __name__ == "__main__":
    raise SystemExit(main())
