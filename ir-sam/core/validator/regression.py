"""Phase 7 — Real regression-test gate.

Replaces the original silent-pass-when-unconfigured behavior with a
typed soft-fail (``TEST_REGRESSION_NOT_CONFIGURED``) plus an
allowlist-secured runner that auto-detects the dominant test harness
in ``project_dir``.

Security model
==============

A regression run executes an *arbitrary* test command inside the
candidate repo, so it is the single largest attack surface in the
validator. The gate therefore enforces a two-layer policy:

1.  **Detect**: locate manifests (``pom.xml``, ``build.gradle``,
    ``pyproject.toml`` / ``pytest.ini``, ``package.json``).
2.  **Allowlist**: every candidate command must appear verbatim in the
    project's ``regression.allowed_commands`` allowlist. The default
    allowlist (used in CI/research mode) contains exactly four well-
    known commands:

    * ``mvn -q -DskipITs test``
    * ``gradle -q test``
    * ``pytest -q``
    * ``npm test --silent``

    Operators that need a different command must list it explicitly
    in their :class:`RegressionConfig`; arbitrary shell strings are
    refused.

Output contract
===============

The gate always returns a :class:`~core.validator.GateOutcome` named
``"regression"``. Possible outcomes:

* ``passed=True,  detail="<runner> ok"`` — chosen command ran and
  returned 0.
* ``passed=False, detail="<runner>: <last-stderr>"`` — command ran
  and returned non-zero.
* ``passed=False, detail="TEST_REGRESSION_NOT_CONFIGURED: ..."`` —
  no allowlisted command applies; the caller must explicitly mark
  the patch as ``validated_only`` rather than ``proven`` per Phase 9.
"""

from __future__ import annotations

import os
import shlex
import shutil
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable

from . import GateOutcome


DEFAULT_ALLOWED_COMMANDS: tuple[str, ...] = (
    "mvn -q -DskipITs test",
    "gradle -q test",
    "pytest -q",
    "npm test --silent",
)


@dataclass(frozen=True)
class RegressionConfig:
    """Per-project regression policy.

    ``allowed_commands`` is the security boundary: nothing outside
    this list may be executed. ``timeout_seconds`` caps each run.
    ``env_allowlist`` is the subset of environment variables that
    will be forwarded into the child process (defaults to none — the
    child sees only ``PATH``).
    """

    allowed_commands: tuple[str, ...] = DEFAULT_ALLOWED_COMMANDS
    timeout_seconds: int = 600
    env_allowlist: tuple[str, ...] = ()

    def is_allowed(self, command: str) -> bool:
        return command.strip() in {c.strip() for c in self.allowed_commands}


@dataclass(frozen=True)
class RegressionPlan:
    """A concrete command we *propose* to run."""

    runner: str           # "maven" | "gradle" | "pytest" | "npm"
    command: str          # full shell-escaped command line
    cwd: Path


def detect_runners(project_dir: Path) -> tuple[RegressionPlan, ...]:
    """Detect candidate test runners in ``project_dir``.

    Returned in priority order (build-system > test-framework).
    The list contains every runner whose manifest exists; the gate
    will execute the first one that is also allowlisted *and* has
    its binary on ``$PATH``.
    """
    plans: list[RegressionPlan] = []
    if (project_dir / "pom.xml").exists():
        plans.append(RegressionPlan(
            "maven", "mvn -q -DskipITs test", project_dir,
        ))
    if (project_dir / "build.gradle").exists() or (project_dir / "build.gradle.kts").exists():
        plans.append(RegressionPlan(
            "gradle", "gradle -q test", project_dir,
        ))
    if (
        (project_dir / "pytest.ini").exists()
        or (project_dir / "pyproject.toml").exists()
        or (project_dir / "tox.ini").exists()
        or any(project_dir.glob("**/test_*.py"))
    ):
        plans.append(RegressionPlan(
            "pytest", "pytest -q", project_dir,
        ))
    if (project_dir / "package.json").exists():
        plans.append(RegressionPlan(
            "npm", "npm test --silent", project_dir,
        ))
    return tuple(plans)


def _binary_for(runner: str) -> str:
    return {
        "maven":  "mvn",
        "gradle": "gradle",
        "pytest": "pytest",
        "npm":    "npm",
    }[runner]


def _safe_env(allowlist: Iterable[str]) -> dict[str, str]:
    env = {"PATH": os.environ.get("PATH", "")}
    for k in allowlist:
        if k in os.environ:
            env[k] = os.environ[k]
    return env


def run_regression_gate(
    project_dir: Path | None,
    config: RegressionConfig | None = None,
) -> GateOutcome:
    """Run the regression gate honoring ``config``.

    Unlike the MVP implementation this never silently passes when no
    runner is configured: such cases produce a typed soft-fail
    (``TEST_REGRESSION_NOT_CONFIGURED``) so that Phase 9's
    ``proof_status`` machinery can downgrade affected patches to
    ``validated_only``.
    """
    cfg = config or RegressionConfig()

    if project_dir is None or not Path(project_dir).exists():
        return GateOutcome(
            "regression", False,
            "TEST_REGRESSION_NOT_CONFIGURED: no project_dir supplied",
        )

    project_dir = Path(project_dir)
    plans = detect_runners(project_dir)
    if not plans:
        return GateOutcome(
            "regression", False,
            "TEST_REGRESSION_NOT_CONFIGURED: no manifest detected "
            "(looked for pom.xml/build.gradle/pyproject.toml/package.json)",
        )

    skipped: list[str] = []
    for plan in plans:
        if not cfg.is_allowed(plan.command):
            skipped.append(f"{plan.runner}:not-in-allowlist")
            continue
        binary = _binary_for(plan.runner)
        if shutil.which(binary) is None:
            skipped.append(f"{plan.runner}:binary-missing")
            continue
        argv = shlex.split(plan.command)
        try:
            r = subprocess.run(
                argv,
                cwd=plan.cwd,
                capture_output=True,
                text=True,
                timeout=cfg.timeout_seconds,
                env=_safe_env(cfg.env_allowlist),
                check=False,
            )
        except subprocess.TimeoutExpired:
            return GateOutcome(
                "regression", False,
                f"{plan.runner} timed out after {cfg.timeout_seconds}s",
            )
        except OSError as exc:
            return GateOutcome(
                "regression", False,
                f"{plan.runner} error: {exc}",
            )
        if r.returncode == 0:
            return GateOutcome(
                "regression", True,
                f"{plan.runner} ok",
            )
        tail = (r.stdout[-500:] + r.stderr[-500:]).strip()
        return GateOutcome(
            "regression", False,
            f"{plan.runner} failed (rc={r.returncode}): {tail}",
        )

    return GateOutcome(
        "regression", False,
        "TEST_REGRESSION_NOT_CONFIGURED: detected runners but none usable "
        f"({'; '.join(skipped)})",
    )


__all__ = [
    "DEFAULT_ALLOWED_COMMANDS",
    "RegressionConfig",
    "RegressionPlan",
    "detect_runners",
    "run_regression_gate",
]
