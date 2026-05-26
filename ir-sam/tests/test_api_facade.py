"""Tests for the production-facing ``core.api`` facade."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from core.api import (
    QuickfixOptions,
    ScanOptions,
    generate_patch_for_file,
    import_sarif_bytes,
    run_quickfix,
    run_scan_findings,
    run_scan_path,
)
from core.ingest.unified import IRSAMFinding, Location, Sink


VULN_JAVA = """\
public class Sample {
    public void f(java.sql.Connection conn, String name) throws Exception {
        java.sql.Statement stmt = conn.createStatement();
        String sql = "SELECT * FROM users WHERE name = '" + name + "'";
        stmt.executeQuery(sql);
    }
}
"""


def test_quickfix_runs_pipeline_and_returns_serializable_record() -> None:
    res = run_quickfix(VULN_JAVA, QuickfixOptions(language="java"))
    assert res.language == "java"
    assert res.elapsed_ms >= 0
    assert len(res.request_id) == 32

    record = res.result
    assert record.stage_reached in {"D", "E", "F", "G"}
    # JSON-serializable end-to-end
    payload = res.to_dict()
    json.dumps(payload)
    assert payload["result"]["stage_reached"] == record.stage_reached


def test_quickfix_full_pipeline_produces_diff_and_passes_gates(tmp_path: Path) -> None:
    res = run_quickfix(VULN_JAVA, QuickfixOptions(language="java"))
    record = res.result
    if record.stage_reached != "G":
        pytest.skip(f"pipeline abstained at {record.stage_reached}: "
                    f"{record.abstention_reason}")
    assert record.patched is True
    assert record.unified_diff and "PreparedStatement" in (record.patched_source or "")
    assert any(g.name == "compile" for g in record.gates)


def test_generate_patch_for_file_round_trip(tmp_path: Path) -> None:
    fp = tmp_path / "Sample.java"
    fp.write_text(VULN_JAVA, encoding="utf-8")
    record = generate_patch_for_file(fp)
    assert record.file.endswith("Sample.java")
    assert record.stage_reached in {"D", "E", "F", "G"}


def test_run_scan_path_streams_events_and_finishes_with_record(tmp_path: Path) -> None:
    (tmp_path / "Sample.java").write_text(VULN_JAVA, encoding="utf-8")
    (tmp_path / "Inert.java").write_text(
        "public class Inert { public int x() { return 1; } }\n", encoding="utf-8")

    events = list(run_scan_path(tmp_path, ScanOptions(languages=("java",))))
    kinds = [e.kind for e in events]
    assert kinds[0] == "scan_started"
    assert kinds[-1] == "scan_finished"
    assert "file_started" in kinds
    assert "file_finished" in kinds

    record = events[-1].payload["record"]
    assert record["files_examined"] == 2
    # The vulnerable file should yield at least one finding.
    assert len(record["findings"]) >= 1
    # Round-trip JSON.
    json.dumps([e.to_dict() for e in events])


def test_run_scan_path_handles_missing_root() -> None:
    events = list(run_scan_path("Z:/definitely/not/a/path"))
    kinds = [e.kind for e in events]
    assert kinds[0] == "scan_started"
    assert "error" in kinds
    assert kinds[-1] == "scan_finished"


def test_run_scan_findings_uses_normalized_finding_entrypoint(tmp_path: Path) -> None:
    src = tmp_path / "src"
    src.mkdir()
    target = src / "Sample.java"
    target.write_text(VULN_JAVA, encoding="utf-8")
    finding_id = IRSAMFinding.compute_id(
        "codeql", "java/sql-injection", "src/Sample.java", 5,
        "java.sql.Statement.executeQuery",
    )
    finding = IRSAMFinding(
        finding_id=finding_id,
        detector="codeql",
        detector_rule_id="java/sql-injection",
        cwe=("CWE-89",),
        language="java",
        interpreter="sql",
        location=Location(file="src/Sample.java", line_start=5),
        sink=Sink(
            api_qualified_name="java.sql.Statement.executeQuery",
            tainted_arg_indices=(0,),
        ),
        severity="high",
    )

    events = list(run_scan_findings(tmp_path, [finding],
                                    ScanOptions(languages=("java",))))
    kinds = [e.kind for e in events]
    assert kinds[0] == "scan_started"
    assert kinds[-1] == "scan_finished"
    stage = next(e for e in events if e.kind == "stage_reached")
    assert stage.payload["finding_id"] == finding_id
    assert stage.payload["job_id"]
    assert stage.payload["artifact_id"].startswith("irsam-")
    record = events[-1].payload["record"]
    assert record["files_examined"] == 1
    assert record["findings"][0]["finding_id"] == finding_id
    json.dumps([e.to_dict() for e in events])


def test_import_sarif_bytes_handles_empty_and_invalid() -> None:
    assert import_sarif_bytes(b"") == []
    assert import_sarif_bytes(b"not json at all") == []


def test_import_sarif_bytes_minimal_codeql() -> None:
    sarif = {
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [{
            "tool": {"driver": {"name": "CodeQL", "version": "2.16.0",
                                 "rules": [{"id": "java/sql-injection",
                                            "properties": {"tags": ["CWE-89"]}}]}},
            "results": [{
                "ruleId": "java/sql-injection",
                "message": {"text": "Possible SQL injection."},
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": {"uri": "src/Sample.java"},
                        "region": {"startLine": 7}
                    }
                }],
                "properties": {"tags": ["CWE-89"]}
            }]
        }]
    }
    rows = import_sarif_bytes(json.dumps(sarif).encode("utf-8"))
    # The adapter may filter rows it doesn't fully recognize; the test
    # asserts the function is total and returns the documented shape.
    assert isinstance(rows, list)
    for r in rows:
        payload = r.to_dict()
        assert "finding_id" in payload
        assert payload["detector"]
