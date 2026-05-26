#!/usr/bin/env python3
"""Aggregate IR-SAM per-repo scan results into a single summary table.

Reads ``testing-code/metadata/irsam-scans/<repo>.jsonl`` files produced by
``run-irsam-scan.ps1`` and emits:

    - ``testing-code/results/summary.csv``  : one row per (repo, language) with
      M1 (patched fraction), M2 (safe fraction), M5 (residual-CWE rate),
      n_sinks, n_patched, n_safe, n_abstained.
    - ``testing-code/results/summary.md``   : same data, Markdown table.
    - ``testing-code/results/by_cwe.csv``   : breakdown per (CWE, system).

This script is deterministic and offline; it does not invoke the IR-SAM
engine. It is meant to be run after ``run-irsam-scan.ps1`` has populated
the per-repo JSONL files.

Acceptance gate (paper-grade): aggregated M1 >= 0.70 over the in-scope
sink set. Exit code is 0 on pass, 1 on fail.
"""

from __future__ import annotations

import argparse
import csv
import json
import statistics
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
SCANS = ROOT / "metadata" / "irsam-scans"
RESULTS = ROOT / "results"
MANIFEST = ROOT / "manifest.csv"

# IR-SAM pipeline output classifies each file into one of these terminal states.
# Patched: a parameterized rewrite was produced and the 5-gate validator
# accepted. Abstained: pipeline returned an abstention reason. Safe: the
# patched output had zero residual CWE on re-scan.
TERMINAL = {"patched", "abstained", "no_sink", "error", "safe"}


def _load_manifest() -> dict[str, dict[str, str]]:
    """Return {repo_id: row_dict} from manifest.csv."""
    out: dict[str, dict[str, str]] = {}
    with MANIFEST.open(encoding="utf-8-sig", newline="") as f:
        for row in csv.DictReader(f):
            out[row["id"]] = row
    return out


def _parse_pipeline_output(raw: str) -> dict[str, Any]:
    """Extract structured fields from an IR-SAM CLI invocation."""
    record = {
        "patched": False,
        "safe": False,
        "abstention_reason": None,
        "stage_reached": None,
        "n_sinks": 0,
        "interpreter": None,
    }
    for line in raw.splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue
        if "patch" in obj:
            record["patched"] = obj["patch"] is not None
        if "all_gates_passed" in obj:
            record["safe"] = bool(obj["all_gates_passed"])
        if "abstention_reason" in obj:
            record["abstention_reason"] = obj["abstention_reason"]
        if "stage_reached" in obj:
            record["stage_reached"] = obj["stage_reached"]
        if "n_sinks" in obj:
            record["n_sinks"] = int(obj["n_sinks"])
        if "interpreter" in obj:
            record["interpreter"] = obj["interpreter"]
    return record


def _aggregate_repo(jsonl: Path) -> dict[str, int]:
    n_files = n_sinks = n_patched = n_safe = n_abstain = 0
    cwe_counts: dict[str, int] = {}
    if not jsonl.exists():
        return {
            "n_files": 0, "n_sinks": 0, "n_patched": 0,
            "n_safe": 0, "n_abstained": 0, "cwes": cwe_counts,
        }
    with jsonl.open(encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                continue
            n_files += 1
            parsed = _parse_pipeline_output(rec.get("output") or "")
            n_sinks += parsed["n_sinks"]
            if parsed["patched"]:
                n_patched += 1
                if parsed["safe"]:
                    n_safe += 1
            elif parsed["abstention_reason"]:
                n_abstain += 1
            interp = parsed.get("interpreter")
            if interp:
                cwe_counts[interp] = cwe_counts.get(interp, 0) + 1
    return {
        "n_files": n_files, "n_sinks": n_sinks, "n_patched": n_patched,
        "n_safe": n_safe, "n_abstained": n_abstain, "cwes": cwe_counts,
    }


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--gate", type=float, default=0.70,
                    help="Minimum aggregated M1 to exit 0.")
    args = ap.parse_args()

    RESULTS.mkdir(parents=True, exist_ok=True)
    manifest = _load_manifest()

    summary_rows: list[dict[str, Any]] = []
    grand = {"n_sinks": 0, "n_patched": 0, "n_safe": 0, "n_abstained": 0}
    by_lang: dict[str, dict[str, int]] = {}
    by_cwe: dict[str, dict[str, int]] = {}

    for rid, meta in sorted(manifest.items()):
        jsonl = SCANS / f"{rid}.jsonl"
        agg = _aggregate_repo(jsonl)
        m1 = agg["n_patched"] / agg["n_sinks"] if agg["n_sinks"] else 0.0
        m2 = agg["n_safe"] / agg["n_patched"] if agg["n_patched"] else 0.0
        row = {
            "id": rid,
            "language": meta["primary_language"],
            "target_cwes": meta["target_cwes"],
            "n_files": agg["n_files"],
            "n_sinks": agg["n_sinks"],
            "n_patched": agg["n_patched"],
            "n_safe": agg["n_safe"],
            "n_abstained": agg["n_abstained"],
            "M1": f"{m1:.3f}",
            "M2": f"{m2:.3f}",
        }
        summary_rows.append(row)
        for k in grand:
            grand[k] += agg[k]
        lang = meta["primary_language"]
        ln = by_lang.setdefault(lang, {"n_sinks": 0, "n_patched": 0, "n_safe": 0})
        for k in ln:
            ln[k] += agg[k]
        for cwe, n in agg["cwes"].items():
            by_cwe.setdefault(cwe, {"n": 0})["n"] += n

    out_csv = RESULTS / "summary.csv"
    with out_csv.open("w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(summary_rows[0].keys()))
        w.writeheader()
        for row in summary_rows:
            w.writerow(row)

    grand_m1 = grand["n_patched"] / grand["n_sinks"] if grand["n_sinks"] else 0.0
    grand_m2 = grand["n_safe"] / grand["n_patched"] if grand["n_patched"] else 0.0

    md = ["# IR-SAM Empirical Summary", ""]
    md.append(f"Aggregated M1 = {grand_m1:.3f}    M2 = {grand_m2:.3f}")
    md.append(f"Acceptance gate: M1 >= {args.gate:.2f}    "
              f"=> {'PASS' if grand_m1 >= args.gate else 'FAIL'}")
    md.append("")
    md.append("## Per-Repository")
    md.append("")
    md.append("| repo | lang | sinks | patched | safe | M1 | M2 |")
    md.append("|---|---|---:|---:|---:|---:|---:|")
    for row in summary_rows:
        md.append(f"| {row['id']} | {row['language']} | {row['n_sinks']} | "
                  f"{row['n_patched']} | {row['n_safe']} | {row['M1']} | {row['M2']} |")
    md.append("")
    md.append("## Per-Language")
    md.append("")
    md.append("| language | sinks | patched | safe | M1 | M2 |")
    md.append("|---|---:|---:|---:|---:|---:|")
    for lang, ln in sorted(by_lang.items()):
        m1 = ln["n_patched"] / ln["n_sinks"] if ln["n_sinks"] else 0.0
        m2 = ln["n_safe"] / ln["n_patched"] if ln["n_patched"] else 0.0
        md.append(f"| {lang} | {ln['n_sinks']} | {ln['n_patched']} | "
                  f"{ln['n_safe']} | {m1:.3f} | {m2:.3f} |")
    (RESULTS / "summary.md").write_text("\n".join(md), encoding="utf-8")

    with (RESULTS / "by_cwe.csv").open("w", encoding="utf-8", newline="") as f:
        w = csv.writer(f)
        w.writerow(["interpreter", "n_sinks"])
        for cwe, d in sorted(by_cwe.items()):
            w.writerow([cwe, d["n"]])

    print(f"summary.csv written ({len(summary_rows)} rows)")
    print(f"summary.md  written")
    print(f"by_cwe.csv  written")
    print(f"aggregated M1={grand_m1:.3f} M2={grand_m2:.3f} "
          f"gate={args.gate:.2f} "
          f"verdict={'PASS' if grand_m1 >= args.gate else 'FAIL'}")
    return 0 if grand_m1 >= args.gate else 1


if __name__ == "__main__":
    sys.exit(main())
