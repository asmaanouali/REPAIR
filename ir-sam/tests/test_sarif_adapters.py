"""Tests for the SARIF adapters (CodeQL / Semgrep / SonarQube)."""

from __future__ import annotations

import json
from pathlib import Path

from core.ingest import codeql, semgrep, sonarqube


def _write_sarif(tmp_path: Path, name: str, doc: dict) -> Path:
    p = tmp_path / name
    p.write_text(json.dumps(doc), encoding="utf-8")
    return p


def _sarif_run(driver: str, rule_id: str, file: str, line: int, msg: str) -> dict:
    return {
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": driver,
                        "semanticVersion": "0.0.0-test",
                        "rules": [
                            {
                                "id": rule_id,
                                "properties": {"tags": ["security", "CWE-89"]},
                            }
                        ],
                    }
                },
                "results": [
                    {
                        "ruleId": rule_id,
                        "message": {"text": msg},
                        "locations": [
                            {
                                "physicalLocation": {
                                    "artifactLocation": {"uri": file},
                                    "region": {"startLine": line},
                                }
                            }
                        ],
                    }
                ],
            }
        ],
    }


def test_codeql_adapter_emits_finding(tmp_path: Path) -> None:
    sarif = _sarif_run(
        "CodeQL", "java/sql-injection", "src/A.java", 12, "tainted SQL"
    )
    p = _write_sarif(tmp_path, "codeql.sarif", sarif)
    findings = list(codeql.adapt(p))
    assert len(findings) == 1
    f = findings[0]
    assert f.detector == "codeql"
    assert f.cwe == ("CWE-89",)
    assert f.interpreter == "sql"
    assert f.language == "java"
    assert f.location.line_start == 12


def test_semgrep_adapter_emits_finding(tmp_path: Path) -> None:
    rid = "java.lang.security.audit.formatted-sql-string.formatted-sql-string"
    sarif = _sarif_run("semgrep", rid, "src/B.java", 7, "concat sql")
    p = _write_sarif(tmp_path, "sg.sarif", sarif)
    findings = list(semgrep.adapt(p))
    assert len(findings) == 1
    assert findings[0].cwe == ("CWE-89",)


def test_sonarqube_adapter_emits_finding(tmp_path: Path) -> None:
    sarif = _sarif_run("SonarQube", "javasecurity:S3649", "src/C.java", 99, "sqli")
    p = _write_sarif(tmp_path, "sq.sarif", sarif)
    findings = list(sonarqube.adapt(p))
    assert len(findings) == 1
    assert findings[0].cwe == ("CWE-89",)


def test_unsupported_sarif_version_rejected(tmp_path: Path) -> None:
    bad = {"version": "1.0.0", "runs": []}
    p = _write_sarif(tmp_path, "bad.sarif", bad)
    import pytest

    with pytest.raises(ValueError):
        list(codeql.adapt(p))
