"""Semgrep CLI runner.

Shells out to ``semgrep scan --config=auto --sarif --quiet
--metrics=off`` against a workspace directory and feeds the resulting
SARIF document through :func:`core.ingest.semgrep.adapt`. The runner
is always attempted; if the ``semgrep`` binary is not on ``$PATH`` it
returns a typed :class:`DetectorUnavailable` outcome rather than
raising.

The set of rules to apply is controlled by the
``IRSAM_SEMGREP_CONFIG`` environment variable. The default is the
repository-local ruleset ``configs/semgrep/irsam-injection.yml``,
which mirrors the registry rule IDs consumed by
:data:`core.ingest.semgrep.SEMGREP_RULE_MAP` and runs deterministically
offline. The registry ``auto`` form is intentionally *not* the default
because it requires network access and is rejected by recent Semgrep
releases when ``--metrics=off`` is set. To use the registry, set
``IRSAM_SEMGREP_CONFIG=auto`` (or a path such as ``p/r2c-security-audit``).
"""

from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
from pathlib import Path

from core.ingest.semgrep import adapt as adapt_semgrep_sarif

from .base import (
    Detector,
    DetectorError,
    DetectorOutcome,
    DetectorUnavailable,
)

_DEFAULT_CONFIG = str(
    Path(__file__).resolve().parents[2]
    / "configs" / "semgrep" / "irsam-injection.yml"
)


class SemgrepRunner:
    """Always-on Semgrep detector."""

    name = "semgrep"

    def __init__(self, config: str | None = None,
                 timeout_seconds: int = 120) -> None:
        self._config = config or os.environ.get(
            "IRSAM_SEMGREP_CONFIG", _DEFAULT_CONFIG,
        )
        self._timeout = timeout_seconds

    def is_available(self) -> bool:
        return shutil.which("semgrep") is not None

    def scan(self, workdir: Path,
             languages: tuple[str, ...] = ()
             ) -> DetectorOutcome | DetectorUnavailable:
        if not self.is_available():
            return DetectorUnavailable(self.name,
                                       "semgrep binary not on PATH")

        workdir = Path(workdir).resolve()
        if not workdir.exists():
            raise DetectorError(f"workdir does not exist: {workdir}")

        with tempfile.TemporaryDirectory(prefix="irsam-semgrep-") as td:
            sarif_path = Path(td) / "out.sarif"
            cmd = [
                "semgrep", "scan",
                "--config", self._config,
                "--sarif", "--output", str(sarif_path),
                "--quiet", "--metrics=off",
                str(workdir),
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
                    f"semgrep timed out after {self._timeout}s"
                ) from exc

            # Semgrep exits 0 (no findings) or 1 (findings present);
            # any other code is a hard error.
            if proc.returncode not in (0, 1):
                raise DetectorError(
                    f"semgrep failed (rc={proc.returncode}): "
                    f"{proc.stderr.strip()[:400]}"
                )

            if not sarif_path.exists():
                # Some semgrep versions write SARIF on stdout when
                # --output is given alongside config issues; the most
                # common failure here is an empty config -> no output.
                return DetectorOutcome(
                    detector=self.name,
                    findings=(),
                    sarif_path=None,
                    stderr_tail=proc.stderr.strip()[-400:],
                )

            findings = tuple(adapt_semgrep_sarif(sarif_path))
            # The SARIF file lives in a temp dir and will be deleted on
            # exit; copy the contents to a persistent path only if the
            # caller asks (current callers do not).
            return DetectorOutcome(
                detector=self.name,
                findings=findings,
                sarif_path=str(sarif_path),
                stderr_tail=proc.stderr.strip()[-400:],
            )


__all__ = ["SemgrepRunner"]
