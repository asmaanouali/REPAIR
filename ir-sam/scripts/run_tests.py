"""Unified IR-SAM test entrypoint.

Tiers (cumulative; each tier subsumes the previous):

    fast     -m "unit or property"                                <= 10 min
    full     fast + integration + e2e + CLI                       <= 30 min
    eval     full + corpus + differential                         (oracle DBs)
    release  eval + mutation + perf + soundness + security        (nightly)

Examples:

    python scripts/run_tests.py fast
    python scripts/run_tests.py full --report-dir reports/test_runs/pr-123
    python scripts/run_tests.py release --no-mutation
"""

from __future__ import annotations

import os
import subprocess
import sys
import time
from pathlib import Path

import typer

app = typer.Typer(no_args_is_help=True, add_completion=False,
                  help="IR-SAM test runner (fast | full | eval | release)")

ROOT = Path(__file__).resolve().parent.parent
DEFAULT_REPORTS = ROOT / "reports" / "test_runs"


def _run(label: str, args: list[str], cwd: Path = ROOT) -> int:
    print(f"\n>>> [{label}] {' '.join(args)}", flush=True)
    t0 = time.monotonic()
    rc = subprocess.call(args, cwd=cwd)
    dt = time.monotonic() - t0
    print(f"<<< [{label}] rc={rc} in {dt:.1f}s", flush=True)
    return rc


def _pytest(marker: str, *, report_dir: Path, extra: list[str] | None = None) -> int:
    report_dir.mkdir(parents=True, exist_ok=True)
    args = [
        sys.executable, "-m", "pytest",
        "-m", marker,
        f"--junitxml={report_dir / 'junit.xml'}",
        "-q",
    ]
    if extra:
        args.extend(extra)
    return _run(f"pytest:{marker}", args)


def _ensure_report_dir(report_dir: Path | None) -> Path:
    if report_dir is None:
        report_dir = DEFAULT_REPORTS / time.strftime("%Y%m%d-%H%M%S")
    report_dir.mkdir(parents=True, exist_ok=True)
    return report_dir


@app.command()
def fast(report_dir: Path = typer.Option(None)) -> None:
    """Lint + type + unit + property (<10 min)."""
    rd = _ensure_report_dir(report_dir)
    rc = 0
    rc |= _run("ruff", [sys.executable, "-m", "ruff", "check", "."])
    rc |= _run("ruff-format", [sys.executable, "-m", "ruff", "format", "--check", "."])
    rc |= _run("mypy", [sys.executable, "-m", "mypy", "core", "bench", "eval"])
    rc |= _pytest("unit or property", report_dir=rd)
    raise typer.Exit(code=rc)


@app.command()
def full(report_dir: Path = typer.Option(None)) -> None:
    """fast + integration + e2e (<30 min)."""
    rd = _ensure_report_dir(report_dir)
    rc = 0
    rc |= _pytest("unit or property or integration or e2e",
                  report_dir=rd, extra=["-n", "auto"])
    raise typer.Exit(code=rc)


@app.command()
def eval(report_dir: Path = typer.Option(None),
         skip_oracle: bool = typer.Option(False, "--skip-oracle")) -> None:
    """full + corpus + differential. Requires the 'oracle' compose profile."""
    rd = _ensure_report_dir(report_dir)
    rc = 0
    rc |= _pytest("unit or property or integration or e2e", report_dir=rd)
    if not skip_oracle:
        rc |= _pytest("differential", report_dir=rd / "differential")
    raise typer.Exit(code=rc)


@app.command()
def release(report_dir: Path = typer.Option(None),
            no_mutation: bool = typer.Option(False, "--no-mutation"),
            no_fuzz: bool = typer.Option(False, "--no-fuzz")) -> None:
    """Full release gate: eval + mutation + perf + soundness + security + fuzz."""
    rd = _ensure_report_dir(report_dir)
    rc = 0
    rc |= _pytest("unit or property or integration or e2e", report_dir=rd)
    rc |= _pytest("differential", report_dir=rd / "differential")
    rc |= _pytest("perf", report_dir=rd / "perf")
    rc |= _pytest("soundness", report_dir=rd / "soundness")
    rc |= _pytest("security", report_dir=rd / "security")
    if not no_mutation:
        (rd / "mutation").mkdir(parents=True, exist_ok=True)
        rc |= _run("mutmut", [sys.executable, "-m", "mutmut", "run"])
    if not no_fuzz:
        rc |= _pytest("fuzz", report_dir=rd / "fuzz")
    raise typer.Exit(code=rc)


if __name__ == "__main__":
    app()
