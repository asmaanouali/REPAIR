"""Juliet test-suite loader (NSA/NIST SARD Juliet 1.3 for Java).

Juliet ships as a directory tree where each leaf contains a
``CWE89_SQL_Injection__connect_tcp_executeBatch_01.java`` style file
with both a vulnerable variant and a "good" variant in the same file
(or sibling files). We pair them up by base-name suffix.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Iterator

from .base import Dataset, VulnSample

CWE_FROM_DIRNAME = re.compile(r"CWE(\d+)_")


class Juliet(Dataset):
    name = "juliet"

    def download(self) -> None:
        target = self.cache_dir / self.name
        if target.exists():
            return
        raise RuntimeError(
            f"Unpack Juliet 1.3 Java test suite into {target} "
            "(download from NIST SARD)."
        )

    def iter_samples(self) -> Iterator[VulnSample]:
        root = self.cache_dir / self.name
        for bad in root.rglob("*bad*.java"):
            m = CWE_FROM_DIRNAME.search(str(bad))
            if not m:
                continue
            cwe = f"CWE-{m.group(1)}"
            good = bad.with_name(bad.name.replace("bad", "good"))
            pre = bad.read_text(encoding="utf-8", errors="replace")
            post = good.read_text(encoding="utf-8", errors="replace") if good.exists() else ""
            yield VulnSample(
                sample_id=f"juliet:{bad.stem}",
                dataset=self.name,
                cwe=(cwe,),
                language="java",
                repo=None,
                commit_fix=None,
                file=str(bad.relative_to(root)),
                pre_fix_code=pre,
                post_fix_code=post,
            )
