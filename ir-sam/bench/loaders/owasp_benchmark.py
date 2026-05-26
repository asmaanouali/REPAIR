"""OWASP Benchmark loader.

The benchmark ships as a Maven project of generated Java sources, each
annotated with a vulnerability category and an oracle (``isTrue`` /
``isFalse``). We treat each ``BenchmarkTest*.java`` file as a sample;
the ``post_fix_code`` is empty (the benchmark provides no human fix —
IR-SAM's job is to synthesize one) and the oracle is consumed by the
validator instead.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Iterator

from .base import Dataset, VulnSample

CATEGORY_TO_CWE = {
    "cmdi": "CWE-78",
    "sqli": "CWE-89",
    "xss":  "CWE-79",
    "ldapi": "CWE-90",
    "xpathi": "CWE-643",
    "pathtraver": "CWE-22",
}


class OWASPBenchmark(Dataset):
    name = "owasp-benchmark"

    def download(self) -> None:
        target = self.cache_dir / self.name
        if target.exists():
            return
        raise RuntimeError(
            f"Clone OWASP Benchmark manually to {target}: "
            "git clone https://github.com/OWASP-Benchmark/BenchmarkJava"
        )

    def iter_samples(self) -> Iterator[VulnSample]:
        root = self.cache_dir / self.name / "BenchmarkJava" / "src" / "main" / "java"
        if not root.exists():
            raise FileNotFoundError(root)
        cat_re = re.compile(r"category\s*=\s*\"(\w+)\"")
        for f in root.rglob("BenchmarkTest*.java"):
            try:
                src = f.read_text(encoding="utf-8")
            except UnicodeDecodeError:
                continue
            m = cat_re.search(src)
            if not m:
                continue
            cwe = CATEGORY_TO_CWE.get(m.group(1))
            if not cwe:
                continue
            yield VulnSample(
                sample_id=f"owasp:{f.stem}",
                dataset=self.name,
                cwe=(cwe,),
                language="java",
                repo="OWASP-Benchmark/BenchmarkJava",
                commit_fix=None,
                file=str(f.relative_to(root)),
                pre_fix_code=src,
                post_fix_code="",
                extra={"category": m.group(1)},
            )
