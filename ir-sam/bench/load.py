"""Unified CLI entrypoint.

    python -m bench.load --datasets cvefixes vul4j bigvul \
        --cache datasets/cache
"""

from __future__ import annotations

import argparse
from pathlib import Path

from .loaders.bigvul import BigVul
from .loaders.cvefixes import CVEFixes
from .loaders.juliet import Juliet
from .loaders.owasp_benchmark import OWASPBenchmark
from .loaders.vul4j import Vul4J

REGISTRY = {
    "cvefixes": CVEFixes,
    "vul4j": Vul4J,
    "bigvul": BigVul,
    "owasp": OWASPBenchmark,
    "juliet": Juliet,
}


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--datasets", nargs="+", choices=list(REGISTRY) + ["all"], default=["all"])
    ap.add_argument("--cache", type=Path, default=Path("datasets/cache"))
    ap.add_argument("--count-only", action="store_true")
    args = ap.parse_args()

    targets = list(REGISTRY) if "all" in args.datasets else args.datasets
    for name in targets:
        cls = REGISTRY[name]
        ds = cls(args.cache)
        try:
            ds.download()
        except RuntimeError as e:
            print(f"[skip] {name}: {e}")
            continue
        if args.count_only:
            try:
                n = sum(1 for _ in ds.iter_samples())
                print(f"{name}: {n} samples")
            except FileNotFoundError as e:
                print(f"[miss] {name}: {e}")
        else:
            print(f"{name}: cached at {args.cache}")


if __name__ == "__main__":
    main()
