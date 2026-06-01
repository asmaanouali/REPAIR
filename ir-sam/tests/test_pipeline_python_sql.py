"""End-to-end pipeline test for the Python/SQL backend (Phase 5)."""

from pathlib import Path

import pytest

from core.ingest.unified import IRSAMFinding, Location, Sink
from core.pipeline import run_finding
from core.pipeline.dispatch import get_backend, supported_backends


_PY_VULNERABLE = '''\
import sqlite3


def get_user(conn, name):
    cur = conn.cursor()
    cur.execute("SELECT id FROM users WHERE name = '" + name + "'")
    return cur.fetchone()
'''


def _make_finding(file: str, line: int) -> IRSAMFinding:
    return IRSAMFinding(
        finding_id="t-py-sql-1",
        detector="semgrep",
        detector_rule_id="python.sqli.concat",
        cwe=("CWE-89",),
        language="python",
        interpreter="sql",
        location=Location(file=file, line_start=line),
        sink=Sink(
            api_qualified_name="sqlite3.Cursor.execute",
            tainted_arg_indices=(0,),
        ),
    )


def test_python_sql_backend_registered():
    assert ("python", "sql") in supported_backends()
    be = get_backend("python", "sql")
    assert be is not None
    assert be.language == "python"
    assert be.interpreter == "sql"


def test_python_sql_end_to_end_concat(tmp_path: Path, monkeypatch):
    # Use the libcst slicer so concat handling is robust.
    monkeypatch.setenv("IRSAM_PY_SLICER", "cst")

    src_file = tmp_path / "vuln.py"
    src_file.write_text(_PY_VULNERABLE, encoding="utf-8")

    sink_line = None
    for i, line in enumerate(_PY_VULNERABLE.splitlines(), start=1):
        if "cur.execute" in line:
            sink_line = i
            break
    assert sink_line is not None

    finding = _make_finding(str(src_file), sink_line)
    out = run_finding(tmp_path, finding)

    # The pipeline should reach stage G and emit a patch.
    assert out.stage_reached == "G", (
        f"abstained at {out.stage_reached}: {out.abstention_reason}"
    )
    assert out.patched, "expected a non-None PatchResult"

    patched = out.patch.patched_source
    # The original concatenation must be gone.
    assert "+ name +" not in patched
    # And the rewritten call must pass parameters via a tuple.
    assert "cur.execute(" in patched
    assert "(name,)" in patched
    # Placeholder must have replaced the host expression.
    assert "?" in patched or "%s" in patched


def test_python_sql_unsupported_interpreter_abstains(tmp_path: Path):
    src_file = tmp_path / "x.py"
    src_file.write_text("x = 1\n", encoding="utf-8")
    f = IRSAMFinding(
        finding_id="t-py-nosql-1",
        detector="semgrep",
        detector_rule_id="python.nosql.injection",
        cwe=("CWE-943",),
        language="python",
        interpreter="nosql",
        location=Location(file=str(src_file), line_start=1),
        sink=Sink(
            api_qualified_name="pymongo.collection.Collection.find",
            tainted_arg_indices=(0,),
        ),
    )
    out = run_finding(tmp_path, f)
    assert out.stage_reached == "A"
    assert (out.abstention_reason or "").startswith("unsupported_backend:")
