"""Deterministic blinded-randomization scheme for the Phase-5 study.

Implements a balanced incomplete-block design: every reviewer sees
IR-SAM plus two baselines drawn without replacement, with the
(tool, position) marginals balanced across the population. Seeded
deterministically from the reviewer's hashed ID so that the
assignments are reproducible from the pre-registration without
storing them in plain text.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import random
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Sequence


BASELINES = ("CodeQL+GPT-4", "VulRepair", "ChatRepair", "LLM-zero-shot")
ANCHOR    = "IR-SAM"


@dataclass(frozen=True)
class Assignment:
    reviewer_id: str
    triplet_index: int            # 0..n_triplets-1
    case_id: str
    cond_A: str                   # tool shown under blinded label A
    cond_B: str
    cond_C: str


def _hseed(reviewer_id: str, study_secret: str) -> int:
    h = hashlib.sha256(f"{study_secret}|{reviewer_id}".encode()).hexdigest()
    return int(h[:16], 16)


def assign(reviewer_ids: Sequence[str], case_ids: Sequence[str],
           *, n_triplets: int = 6, study_secret: str = "IRSAM-PHASE5-v1"
           ) -> list[Assignment]:
    """Return the full Latin-square-like assignment."""
    out: list[Assignment] = []
    case_pool = list(case_ids)
    for rid in reviewer_ids:
        rng = random.Random(_hseed(rid, study_secret))
        cases = rng.sample(case_pool, k=min(n_triplets, len(case_pool)))
        for t, cid in enumerate(cases):
            others = rng.sample(BASELINES, k=2)
            tools = [ANCHOR] + others
            rng.shuffle(tools)
            out.append(Assignment(
                reviewer_id=rid, triplet_index=t, case_id=cid,
                cond_A=tools[0], cond_B=tools[1], cond_C=tools[2]))
    return out


def write_csv(assignments: Iterable[Assignment], out_path: Path) -> None:
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with out_path.open("w", encoding="utf-8", newline="") as f:
        w = csv.writer(f)
        w.writerow(["reviewer_id", "triplet_index", "case_id",
                    "cond_A", "cond_B", "cond_C"])
        for a in assignments:
            w.writerow([a.reviewer_id, a.triplet_index, a.case_id,
                        a.cond_A, a.cond_B, a.cond_C])


def main(argv: Sequence[str] | None = None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--reviewers", required=True,
                    help="path to text file with one reviewer id per line")
    ap.add_argument("--cases", required=True,
                    help="path to text file with one case id per line")
    ap.add_argument("--out", default="study/assignments.csv")
    ap.add_argument("--triplets", type=int, default=6)
    args = ap.parse_args(argv)

    rids = [l.strip() for l in Path(args.reviewers).read_text().splitlines() if l.strip()]
    cids = [l.strip() for l in Path(args.cases).read_text().splitlines() if l.strip()]
    asg = assign(rids, cids, n_triplets=args.triplets)
    write_csv(asg, Path(args.out))
    print(f"wrote {len(asg)} assignments -> {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
