"""Vul4J loader (Bui et al., MSR 2022).

Vul4J ships as a Git repository of reproducible Java vulnerabilities,
each containing a ``vulnerability_info.json`` and reproducer scripts.
This loader expects the repo to be already cloned at ``cache_dir/vul4j``
(``git clone https://github.com/tuhh-softsec/vul4j``).
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Iterator

from .base import Dataset, VulnSample


class Vul4J(Dataset):
    name = "vul4j"

    def download(self) -> None:
        root = self.cache_dir / self.name
        if root.exists():
            return
        raise RuntimeError(
            "Vul4J must be cloned manually: "
            f"git clone https://github.com/tuhh-softsec/vul4j {root}"
        )

    def iter_samples(self) -> Iterator[VulnSample]:
        root = self.cache_dir / self.name / "vul4j"
        for info in root.rglob("vulnerability_info.json"):
            try:
                meta = json.loads(info.read_text(encoding="utf-8"))
            except json.JSONDecodeError:
                continue
            vid = meta.get("vul_id") or info.parent.name
            cwes = tuple(meta.get("cwe_id", "").split(",")) if meta.get("cwe_id") else ()
            for fc in meta.get("human_patch", []):
                fpath = fc.get("file_path", "")
                yield VulnSample(
                    sample_id=f"vul4j:{vid}:{fpath}",
                    dataset=self.name,
                    cwe=cwes,
                    language="java",
                    repo=meta.get("project"),
                    commit_fix=meta.get("human_patch_commit"),
                    file=fpath,
                    pre_fix_code=fc.get("code_before", ""),
                    post_fix_code=fc.get("code_after", ""),
                    cve=meta.get("cve_id"),
                )
