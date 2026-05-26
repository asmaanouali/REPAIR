"""CodeQL CLI runner (opt-in).

Activates only when the ``IRSAM_CODEQL_BIN`` environment variable
points to a ``codeql`` executable. CodeQL requires a database build
step before query evaluation; this runner can be configured one of
two ways:

1. **Pre-built database**: set ``IRSAM_CODEQL_DB`` to the database
   path. The runner runs ``codeql database analyze`` and parses the
   resulting SARIF.

2. **Build on demand**: not implemented in this milestone. The runner
   returns :class:`DetectorUnavailable` with reason ``"no codeql
   database configured"``.

The query suite is selected via ``IRSAM_CODEQL_SUITE`` (default:
``codeql/<lang>-queries:security-and-quality.qls``). Language is read
from the ``languages`` argument or, failing that, from
``IRSAM_CODEQL_LANG`` (default: ``java``).
"""

from __future__ import annotations

import os
import subprocess
import tempfile
from pathlib import Path

from core.ingest.codeql import adapt as adapt_codeql_sarif

from .base import (
    DetectorError,
    DetectorOutcome,
    DetectorUnavailable,
)


class CodeQLRunner:
    name = "codeql"

    def __init__(self, timeout_seconds: int = 600) -> None:
        self._bin = os.environ.get("IRSAM_CODEQL_BIN")
        self._db = os.environ.get("IRSAM_CODEQL_DB")
        self._suite = os.environ.get(
            "IRSAM_CODEQL_SUITE",
            "",  # filled in lazily from language
        )
        self._lang_env = os.environ.get("IRSAM_CODEQL_LANG", "java")
        self._timeout = timeout_seconds

    def is_available(self) -> bool:
        return bool(self._bin) and Path(self._bin or "").exists()

    def scan(self, workdir: Path,
             languages: tuple[str, ...] = ()
             ) -> DetectorOutcome | DetectorUnavailable:
        if not self.is_available():
            return DetectorUnavailable(
                self.name,
                "IRSAM_CODEQL_BIN not set or binary not found",
            )
        if not self._db:
            return DetectorUnavailable(
                self.name,
                "no codeql database configured (set IRSAM_CODEQL_DB)",
            )

        lang = languages[0] if languages else self._lang_env
        suite = (
            self._suite
            or f"codeql/{lang}-queries:codeql-suites/{lang}-security-and-quality.qls"
        )

        with tempfile.TemporaryDirectory(prefix="irsam-codeql-") as td:
            sarif_path = Path(td) / "out.sarif"
            cmd = [
                self._bin or "codeql",
                "database", "analyze",
                self._db,
                suite,
                "--format=sarif-latest",
                f"--output={sarif_path}",
                "--quiet",
            ]
            try:
                proc = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    timeout=self._timeout,
                    check=False,
                )
            except subprocess.TimeoutExpired as exc:
                raise DetectorError(
                    f"codeql timed out after {self._timeout}s"
                ) from exc

            if proc.returncode != 0 or not sarif_path.exists():
                raise DetectorError(
                    f"codeql failed (rc={proc.returncode}): "
                    f"{proc.stderr.strip()[:400]}"
                )

            findings = tuple(adapt_codeql_sarif(sarif_path))
            return DetectorOutcome(
                detector=self.name,
                findings=findings,
                sarif_path=str(sarif_path),
                stderr_tail=proc.stderr.strip()[-400:],
            )


__all__ = ["CodeQLRunner"]
