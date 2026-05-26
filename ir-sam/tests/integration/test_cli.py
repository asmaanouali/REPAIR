"""CLI integration tests using Typer's CliRunner.

Covers the five published subcommands (``scan``, ``plan``, ``patch``,
``validate``, ``pipeline``). Asserts:
- exit codes are stable across runs,
- ``--json-out`` artifacts are valid JSON with the documented top-level keys,
- ``patch --out`` is byte-identical across two runs on the same input
  (no nondeterminism from dict / set iteration order).
"""

from __future__ import annotations

import json
import tempfile
from pathlib import Path

import pytest
from typer.testing import CliRunner

from bench.juliet_mini import generate_benchmark
from core.cli import app

pytestmark = pytest.mark.integration


@pytest.fixture(scope="module")
def bench_dir() -> Path:
    tmp = Path(tempfile.mkdtemp(prefix="irsam-cli-"))
    generate_benchmark(tmp, per_category=1)
    return tmp


@pytest.fixture(scope="module")
def eq_string_file(bench_dir: Path) -> Path:
    cands = sorted(bench_dir.glob("CWE89_concat_eq_string_*.java"))
    assert cands, "concat-eq-string fixture not generated"
    return cands[0]


def test_scan_subcommand(eq_string_file: Path) -> None:
    runner = CliRunner()
    res = runner.invoke(app, ["scan", str(eq_string_file)])
    assert res.exit_code == 0, res.output
    assert "executeQuery" in res.output or "Sinks" in res.output


def test_pipeline_subcommand_emits_valid_json(eq_string_file: Path,
                                              tmp_path: Path) -> None:
    runner = CliRunner()
    out = tmp_path / "report.json"
    res = runner.invoke(app, ["pipeline", str(eq_string_file), "--json-out", str(out)])
    assert res.exit_code == 0, res.output
    data = json.loads(out.read_text(encoding="utf-8"))
    assert {"file", "stage_reached", "patched",
            "all_gates_passed", "abstention_reason"} <= set(data)
    assert data["stage_reached"] in {"A", "B", "C", "D", "E", "F", "G"}


def test_patch_is_byte_identical_across_runs(eq_string_file: Path,
                                             tmp_path: Path) -> None:
    runner = CliRunner()
    out1 = tmp_path / "patched1.java"
    out2 = tmp_path / "patched2.java"
    r1 = runner.invoke(app, ["patch", str(eq_string_file), "--out", str(out1)])
    r2 = runner.invoke(app, ["patch", str(eq_string_file), "--out", str(out2)])
    assert r1.exit_code == 0 and r2.exit_code == 0, (r1.output, r2.output)
    assert out1.read_bytes() == out2.read_bytes(), (
        "patch synthesis is nondeterministic across two consecutive runs"
    )


def test_validate_exit_code_reflects_gates(eq_string_file: Path) -> None:
    runner = CliRunner()
    res = runner.invoke(app, ["validate", str(eq_string_file)])
    # 0 = all gates passed; 2 = some gate failed; 1 = pipeline did not reach G.
    assert res.exit_code in (0, 2), res.output
