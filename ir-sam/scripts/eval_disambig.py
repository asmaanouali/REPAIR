"""A/B evaluation of the Stage-D disambiguator policies.

Compares :class:`core.disambig.ModelPolicy` (when ``IR_SAM_DISAMBIG_MODEL``
is set) against :class:`core.disambig.HeuristicPolicy` on the held-out
test split produced by :mod:`bench.disambig_corpus`.

Reports:

* per-policy accuracy (macro + per label-set)
* expected calibration error (ECE, 15 bins)
* confidence histogram
* threshold-fallback rate at the configured threshold
* per-example disagreement listing (CSV)

Usage::

    python -m scripts.eval_disambig \
        --corpus-dir reports/disambig_corpus \
        --out reports/disambig_eval.json \
        --model-checkpoint reports/disambig_ckpts/codet5p-220m-v1

If ``--model-checkpoint`` is omitted, the model policy is skipped and
only the heuristic baseline is reported.
"""

from __future__ import annotations

import argparse
import csv
import json
import os
import sys
from collections import defaultdict
from pathlib import Path

from bench.disambig_corpus import Example, iter_jsonl
from core.disambig import HeuristicPolicy, ModelPolicy, Question


def _build_argparser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="Evaluate disambiguator policies.")
    p.add_argument("--corpus-dir", required=True, type=Path)
    p.add_argument("--split", default="test", choices=("train", "valid", "test"))
    p.add_argument("--out", required=True, type=Path,
                   help="Path to write the JSON report.")
    p.add_argument("--disagreements-csv", type=Path, default=None)
    p.add_argument("--model-checkpoint", default=None,
                   help="If set, evaluate ModelPolicy with this checkpoint.")
    p.add_argument("--threshold", type=float, default=0.5)
    return p


def _to_question(ex: Example) -> Question:
    from core.disambig import labels as label_schema
    ls = label_schema.get(ex.interpreter, ex.site)
    return Question(
        sig_text=ex.sig_text,
        context=ex.context,
        labels=ls.labels,
        interpreter=ex.interpreter,
        site=ex.site,
    )


def _ece(confidences: list[float], corrects: list[bool], bins: int = 15) -> float:
    """Expected Calibration Error, 15-bin reliability."""
    if not confidences:
        return 0.0
    edges = [i / bins for i in range(bins + 1)]
    n = len(confidences)
    ece = 0.0
    for lo, hi in zip(edges[:-1], edges[1:]):
        idx = [i for i, c in enumerate(confidences) if lo <= c < hi or
               (hi == 1.0 and c == 1.0)]
        if not idx:
            continue
        acc = sum(corrects[i] for i in idx) / len(idx)
        conf = sum(confidences[i] for i in idx) / len(idx)
        ece += (len(idx) / n) * abs(acc - conf)
    return ece


def _eval_policy(policy, examples: list[Example]) -> dict:
    correct: list[bool] = []
    conf: list[float] = []
    per_set: dict[tuple[str, str], list[bool]] = defaultdict(list)
    rows: list[dict] = []
    fallback_count = 0
    for ex in examples:
        q = _to_question(ex)
        ans = policy.choose(q)
        ok = ans.label == ex.label
        correct.append(ok)
        conf.append(float(ans.confidence))
        per_set[(ex.interpreter, ex.site)].append(ok)
        if "fallback" in ans.source or "low-confidence" in ans.source:
            fallback_count += 1
        rows.append({
            "interpreter": ex.interpreter, "site": ex.site,
            "gold": ex.label, "pred": ans.label,
            "confidence": ans.confidence, "source": ans.source,
            "correct": ok,
        })
    n = len(examples) or 1
    return {
        "overall_accuracy": sum(correct) / n,
        "macro_accuracy_by_site": {
            f"{k[0]}/{k[1]}": (sum(v) / len(v)) for k, v in per_set.items()
        },
        "ece": _ece(conf, correct),
        "fallback_rate": fallback_count / n,
        "n": n,
        "_rows": rows,
    }


def main(argv: list[str] | None = None) -> int:
    args = _build_argparser().parse_args(argv)
    split_path = args.corpus_dir / f"{args.split}.jsonl"
    if not split_path.exists():
        print(f"[eval_disambig] ERROR: {split_path} missing.", file=sys.stderr)
        return 2
    examples = list(iter_jsonl(split_path))
    if not examples:
        print(f"[eval_disambig] ERROR: empty split at {split_path}.",
              file=sys.stderr)
        return 2

    os.environ.setdefault("IR_SAM_DISAMBIG_THRESHOLD", str(args.threshold))

    report: dict = {
        "split": args.split, "n": len(examples),
        "threshold": args.threshold,
    }
    heuristic_eval = _eval_policy(HeuristicPolicy(), examples)
    report["heuristic"] = {k: v for k, v in heuristic_eval.items() if k != "_rows"}

    if args.model_checkpoint:
        model_eval = _eval_policy(
            ModelPolicy(args.model_checkpoint), examples,
        )
        report["model"] = {k: v for k, v in model_eval.items() if k != "_rows"}
        if args.disagreements_csv:
            args.disagreements_csv.parent.mkdir(parents=True, exist_ok=True)
            with args.disagreements_csv.open("w", encoding="utf-8", newline="") as fh:
                w = csv.DictWriter(
                    fh,
                    fieldnames=("interpreter", "site", "gold",
                                "heuristic_pred", "model_pred",
                                "heuristic_conf", "model_conf"),
                )
                w.writeheader()
                for hr, mr in zip(heuristic_eval["_rows"], model_eval["_rows"]):
                    if hr["pred"] != mr["pred"]:
                        w.writerow({
                            "interpreter": hr["interpreter"], "site": hr["site"],
                            "gold": hr["gold"],
                            "heuristic_pred": hr["pred"], "model_pred": mr["pred"],
                            "heuristic_conf": hr["confidence"],
                            "model_conf": mr["confidence"],
                        })

    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(report, indent=2, sort_keys=True),
                        encoding="utf-8")
    print(f"[eval_disambig] OK: wrote report to {args.out}")
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
