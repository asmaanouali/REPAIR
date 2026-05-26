"""BigVul loader (Fan et al., MSR 2020).

BigVul is distributed as a CSV (``MSR_data_cleaned.csv``). This loader
streams it row-by-row and emits one VulnSample per (cve, file) pair.
"""

from __future__ import annotations

import csv
from pathlib import Path
from typing import Iterator

from .base import Dataset, VulnSample


class BigVul(Dataset):
    name = "bigvul"
    CSV_NAME = "MSR_data_cleaned.csv"

    def download(self) -> None:
        target = self.cache_dir / self.name / self.CSV_NAME
        if target.exists():
            return
        raise RuntimeError(
            f"Place BigVul CSV manually at {target}. Source: Fan et al., MSR 2020."
        )

    def iter_samples(self) -> Iterator[VulnSample]:
        csv_path = self.cache_dir / self.name / self.CSV_NAME
        if not csv_path.exists():
            raise FileNotFoundError(csv_path)
        with csv_path.open(encoding="utf-8", newline="") as f:
            reader = csv.DictReader(f)
            for row in reader:
                cwe_raw = (row.get("CWE ID") or "").strip()
                cwes = (cwe_raw,) if cwe_raw.startswith("CWE-") else ()
                yield VulnSample(
                    sample_id=f"bigvul:{row.get('commit_id', '')}:{row.get('file_name', '')}",
                    dataset=self.name,
                    cwe=cwes,
                    language=(row.get("lang") or row.get("Programming Language") or "").lower(),
                    repo=row.get("project") or None,
                    commit_fix=row.get("commit_id") or None,
                    file=row.get("file_name", ""),
                    pre_fix_code=row.get("func_before") or "",
                    post_fix_code=row.get("func_after") or "",
                    cve=row.get("CVE ID") or None,
                )
