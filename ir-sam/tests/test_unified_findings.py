"""Tests for the unified finding model + schema."""

from __future__ import annotations

import json

import pytest

from core.ingest.unified import (
    Evidence,
    IRSAMFinding,
    Location,
    Sink,
    dedup_findings,
    validate_finding,
)


def _sample_finding() -> IRSAMFinding:
    return IRSAMFinding(
        finding_id=IRSAMFinding.compute_id(
            "codeql", "java/sql-injection",
            "src/A.java", 42, "java.sql.Statement.executeQuery",
        ),
        detector="codeql",
        detector_rule_id="java/sql-injection",
        cwe=("CWE-89",),
        language="java",
        interpreter="sql",
        location=Location(file="src/A.java", line_start=42, line_end=42),
        sink=Sink(
            api_qualified_name="java.sql.Statement.executeQuery",
            tainted_arg_indices=(0,),
        ),
        evidence=Evidence(full_message="tainted SQL string"),
    )


def test_finding_roundtrip_matches_schema() -> None:
    f = _sample_finding()
    payload = f.to_dict()
    validate_finding(payload)
    # JSON round-trip
    payload2 = json.loads(json.dumps(payload))
    validate_finding(payload2)


def test_finding_id_is_stable() -> None:
    a = _sample_finding()
    b = _sample_finding()
    assert a.finding_id == b.finding_id


def test_dedup_collapses_cross_detector_duplicates() -> None:
    a = _sample_finding()
    b_payload = a.to_dict()
    b_payload["detector"] = "semgrep"
    b_payload["detector_rule_id"] = "java.lang.security.audit.formatted-sql-string.formatted-sql-string"
    b_payload["finding_id"] = IRSAMFinding.compute_id(
        "semgrep", b_payload["detector_rule_id"],
        b_payload["location"]["file"], b_payload["location"]["line_start"],
        b_payload["sink"]["api_qualified_name"],
    )
    validate_finding(b_payload)
    # rebuild
    from core.ingest.unified import _finding_from_dict  # type: ignore

    b = _finding_from_dict(b_payload)
    out = dedup_findings([a, b])
    assert len(out) == 1


def test_invalid_cwe_format_rejected() -> None:
    f = _sample_finding()
    payload = f.to_dict()
    payload["cwe"] = ["sqli"]
    with pytest.raises(Exception):
        validate_finding(payload)
