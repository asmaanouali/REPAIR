"""CVEfixes loader (Bhandari et al., MSR 2021).

The dataset is published as a SQLite dump (~ 2 GB compressed) plus a
schema document. We cache the SQLite file under ``cache_dir/cvefixes/``
and stream samples from it.

We do **not** vendor the dataset; users must accept the dataset's
license and run ``CVEFixes.download()`` once. The URL is read from
``CVEFIXES_URL`` env-var to keep the repository free of links that
might rot.
"""

from __future__ import annotations

import hashlib
import os
import sqlite3
from pathlib import Path
from typing import Iterator

import requests

from .base import Dataset, VulnSample


class CVEFixes(Dataset):
    name = "cvefixes"

    SQLITE_NAME = "CVEfixes.sqlite"
    EXPECTED_SHA256: str | None = None  # set per release

    def download(self) -> None:
        target = self.cache_dir / self.name / self.SQLITE_NAME
        target.parent.mkdir(parents=True, exist_ok=True)
        if target.exists():
            return
        url = os.environ.get("CVEFIXES_URL")
        if not url:
            raise RuntimeError(
                "Set CVEFIXES_URL to the dataset download URL (see "
                "the CVEfixes paper for the canonical source)."
            )
        with requests.get(url, stream=True, timeout=60) as r:
            r.raise_for_status()
            with target.open("wb") as f:
                for chunk in r.iter_content(chunk_size=1 << 20):
                    if chunk:
                        f.write(chunk)
        if self.EXPECTED_SHA256 is not None:
            self._verify_checksum(target)

    def _verify_checksum(self, p: Path) -> None:
        h = hashlib.sha256()
        with p.open("rb") as f:
            for chunk in iter(lambda: f.read(1 << 20), b""):
                h.update(chunk)
        if h.hexdigest() != self.EXPECTED_SHA256:
            raise RuntimeError(f"checksum mismatch for {p}")

    def iter_samples(self) -> Iterator[VulnSample]:
        db = self.cache_dir / self.name / self.SQLITE_NAME
        if not db.exists():
            raise FileNotFoundError(f"{db} not found; run .download() first")
        conn = sqlite3.connect(db)
        try:
            cur = conn.cursor()
            # NOTE: column names follow CVEfixes v1.0.7 schema.
            cur.execute(
                """
                SELECT fc.hash, c.cve_id, fc.programming_language,
                       fc.filename, fc.old_path, fc.new_path,
                       fc.diff_parsed, fc.code_before, fc.code_after,
                       c.cwe_id, fc.repo_url
                  FROM file_change fc
                  JOIN commits cm ON cm.hash = fc.hash
                  JOIN fixes fx  ON fx.hash = cm.hash
                  JOIN cve c     ON c.cve_id = fx.cve_id
                 WHERE fc.code_before IS NOT NULL
                   AND fc.code_after  IS NOT NULL
                """
            )
            for (sha, cve_id, lang, fname, _old, _new,
                 _diff, before, after, cwe_id, repo_url) in cur:
                cwes = tuple(
                    f"CWE-{x.strip().removeprefix('CWE-')}"
                    for x in (cwe_id or "").split(",") if x.strip()
                )
                yield VulnSample(
                    sample_id=f"cvefixes:{sha}:{fname}",
                    dataset=self.name,
                    cwe=cwes,
                    language=(lang or "").lower() or "unknown",
                    repo=_repo_owner_name(repo_url),
                    commit_fix=sha,
                    file=fname,
                    pre_fix_code=before,
                    post_fix_code=after,
                    cve=cve_id,
                )
        finally:
            conn.close()


def _repo_owner_name(url: str | None) -> str | None:
    if not url:
        return None
    # https://github.com/owner/repo[.git] -> owner/repo
    parts = url.rstrip("/").removesuffix(".git").split("/")
    if len(parts) >= 2:
        return f"{parts[-2]}/{parts[-1]}"
    return None
