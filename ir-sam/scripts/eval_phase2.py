"""Phase-2 acceptance evaluation: run the IR-SAM pipeline over the
Juliet-mini synthetic benchmark and emit the gate verdict the user
requested: >=80 percent successful patches on cases tagged
``expected_pipeline_outcome="patched"``, and 0 residual CWE-89 in the
emitted patches.

Usage
~~~~~

    python scripts/eval_phase2.py [--per-category 5] [--out reports/]

Produces:
    reports/phase2_eval.csv        # per-case outcome
    reports/phase2_eval.json       # full machine-readable record
    reports/phase2_summary.txt     # human verdict
"""

from __future__ import annotations

import argparse
import json
import sys
import tempfile
from dataclasses import asdict
from pathlib import Path

# allow running directly without `pip install -e`
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from bench.juliet_mini import BenchCase, generate_benchmark  # noqa: E402
from core.pipeline import run_file  # noqa: E402


# Allow-lists used by the pipeline for ORDER BY identifier cases:
# the synthetic bench uses Java constant ``ALLOWED_COLS``.
DEFAULT_ALLOWLISTS = {"h0": "ALLOWED_COLS"}


def _row(case: BenchCase, outcome) -> dict:
    gates = []
    if outcome.gates is not None:
        for g in outcome.gates.gates:
            gates.append({"name": g.name, "passed": g.passed, "detail": g.detail})
    return {
        "name": case.name,
        "category": case.category,
        "expected_outcome": case.expected_pipeline_outcome,
        "expected_abstain_stage": case.expected_abstain_stage,
        "stage_reached": outcome.stage_reached,
        "abstention_reason": outcome.abstention_reason,
        "all_gates_passed": (outcome.gates is not None and
                              outcome.gates.overall_passed),
        "gates": gates,
    }


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--per-category", type=int, default=5)
    ap.add_argument("--out", type=str, default="reports")
    args = ap.parse_args()

    out_dir = Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)

    with tempfile.TemporaryDirectory() as tmp:
        bench_dir = Path(tmp) / "bench"
        cases = generate_benchmark(bench_dir, per_category=args.per_category)

        rows: list[dict] = []
        for case in cases:
            java_path = bench_dir / f"{case.name}.java"
            allow = DEFAULT_ALLOWLISTS if case.category == "concat-orderby-ident" else None
            try:
                outcome = run_file(java_path, allowlists=allow)
            except Exception as e:  # pragma: no cover - safety net
                rows.append({
                    "name": case.name, "category": case.category,
                    "expected_outcome": case.expected_pipeline_outcome,
                    "expected_abstain_stage": case.expected_abstain_stage,
                    "stage_reached": "EXC",
                    "abstention_reason": f"exception:{e!r}",
                    "all_gates_passed": False,
                    "gates": [],
                })
                continue
            rows.append(_row(case, outcome))

    # ----- aggregate ---------------------------------------------------
    patched_cases = [r for r in rows if r["expected_outcome"] == "patched"]
    abstain_cases = [r for r in rows if r["expected_outcome"] == "abstain"]

    patched_pass = [r for r in patched_cases if r["all_gates_passed"]]
    abstain_correct = [r for r in abstain_cases
                       if r["stage_reached"] == r["expected_abstain_stage"]]

    # gate-by-gate stats over patched-expected cases that reached G
    gate_stats: dict[str, dict[str, int]] = {}
    for r in patched_cases:
        for g in r["gates"]:
            d = gate_stats.setdefault(g["name"], {"passed": 0, "total": 0})
            d["total"] += 1
            if g["passed"]:
                d["passed"] += 1

    # residual CWE-89 in the emitted patches = number of patched-expected
    # cases whose re-SAST gate failed
    residual = 0
    for r in patched_cases:
        for g in r["gates"]:
            if g["name"] == "re-SAST" and not g["passed"]:
                residual += 1

    patch_applicability = (
        len([r for r in patched_cases if r["stage_reached"] == "G"])
        / max(len(patched_cases), 1)
    )
    patch_pass_rate = len(patched_pass) / max(len(patched_cases), 1)
    abstain_accuracy = len(abstain_correct) / max(len(abstain_cases), 1)

    # ----- emit --------------------------------------------------------
    csv_path = out_dir / "phase2_eval.csv"
    with csv_path.open("w", encoding="utf-8") as f:
        f.write("name,category,expected_outcome,stage_reached,all_gates_passed,abstention_reason\n")
        for r in rows:
            f.write(f'{r["name"]},{r["category"]},{r["expected_outcome"]},'
                    f'{r["stage_reached"]},{r["all_gates_passed"]},'
                    f'{(r["abstention_reason"] or "").replace(chr(10), " ")}\n')

    json_path = out_dir / "phase2_eval.json"
    json_path.write_text(json.dumps({
        "rows": rows,
        "summary": {
            "total_cases": len(rows),
            "patched_expected": len(patched_cases),
            "patched_passed_all_gates": len(patched_pass),
            "abstain_expected": len(abstain_cases),
            "abstain_correctly_at_stage": len(abstain_correct),
            "patch_applicability": patch_applicability,
            "patch_gate_pass_rate": patch_pass_rate,
            "abstain_accuracy": abstain_accuracy,
            "residual_cwe89": residual,
            "gate_breakdown": gate_stats,
        },
    }, indent=2), encoding="utf-8")

    verdict_pass = (patch_pass_rate >= 0.80) and (residual == 0)
    lines: list[str] = []
    lines.append("IR-SAM Phase-2 acceptance evaluation")
    lines.append("=" * 50)
    lines.append(f"Total cases:               {len(rows)}")
    lines.append(f"Patched-expected cases:    {len(patched_cases)}")
    lines.append(f"  reached stage G:         "
                 f"{len([r for r in patched_cases if r['stage_reached'] == 'G'])}")
    lines.append(f"  all 5 gates passed:      {len(patched_pass)}")
    lines.append(f"Abstain-expected cases:    {len(abstain_cases)}")
    lines.append(f"  abstained at expected:   {len(abstain_correct)}")
    lines.append("")
    lines.append(f"Patch applicability:       {patch_applicability * 100:6.2f} %")
    lines.append(f"Patch gate-pass rate:      {patch_pass_rate * 100:6.2f} %")
    lines.append(f"Abstain accuracy:          {abstain_accuracy * 100:6.2f} %")
    lines.append(f"Residual CWE-89:           {residual}")
    lines.append("")
    lines.append("Gate breakdown (patched-expected cases):")
    for name, d in gate_stats.items():
        rate = d["passed"] / max(d["total"], 1) * 100
        lines.append(f"  {name:<14s}  {d['passed']:3d}/{d['total']:3d}  ({rate:6.2f} %)")
    lines.append("")
    lines.append(f"Acceptance gate: patch pass-rate >= 80 %  AND  residual == 0")
    lines.append(f"  patch pass-rate  : {patch_pass_rate * 100:6.2f} %   "
                 f"({'PASS' if patch_pass_rate >= 0.80 else 'FAIL'})")
    lines.append(f"  residual CWE-89  : {residual:>6d}     "
                 f"({'PASS' if residual == 0 else 'FAIL'})")
    lines.append("")
    lines.append(f"VERDICT: {'PASS' if verdict_pass else 'FAIL'}")

    summary = "\n".join(lines) + "\n"
    (out_dir / "phase2_summary.txt").write_text(summary, encoding="utf-8")
    print(summary)
    return 0 if verdict_pass else 1


if __name__ == "__main__":
    sys.exit(main())
