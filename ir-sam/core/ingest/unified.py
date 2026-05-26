"""Unified finding model and loader.

The class :class:`IRSAMFinding` is the single record type that downstream
stages (B-Slice through G-Validator) consume. Detector-specific adapters
in :mod:`core.ingest.codeql`, :mod:`core.ingest.semgrep`, and
:mod:`core.ingest.sonarqube` produce instances of this class from SARIF
2.1.0 documents.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Iterable, Literal

import jsonschema

_SCHEMA_PATH = Path(__file__).resolve().parents[2] / "schemas" / "irsam-finding.schema.json"
_SCHEMA: dict[str, Any] = json.loads(_SCHEMA_PATH.read_text(encoding="utf-8"))


Detector = Literal["codeql", "semgrep", "sonarqube", "joern", "other"]
Interpreter = Literal[
    "sql", "shell", "html-dom", "ldap", "xpath", "template", "path", "xml", "other"
]
Language = Literal["java", "python"]
Severity = Literal["info", "low", "medium", "high", "critical"]


@dataclass(frozen=True)
class Location:
    file: str
    line_start: int
    line_end: int | None = None
    column_start: int | None = None
    column_end: int | None = None
    function: str | None = None
    method_signature: str | None = None


@dataclass(frozen=True)
class Sink:
    api_qualified_name: str
    tainted_arg_indices: tuple[int, ...]


@dataclass(frozen=True)
class TaintSource:
    api_qualified_name: str
    location: Location | None = None


@dataclass(frozen=True)
class Evidence:
    snippet: str | None = None
    full_message: str | None = None
    sarif_blob_sha256: str | None = None


@dataclass(frozen=True)
class IRSAMFinding:
    """Detector-agnostic finding consumed by stage A."""

    finding_id: str
    detector: Detector
    detector_rule_id: str
    cwe: tuple[str, ...]
    language: Language
    interpreter: Interpreter
    location: Location
    sink: Sink
    schema_version: str = "1.0.0"
    detector_version: str | None = None
    severity: Severity | None = None
    taint_sources: tuple[TaintSource, ...] = field(default_factory=tuple)
    evidence: Evidence | None = None
    confidence: float | None = None
    dedup_key: str | None = None

    @staticmethod
    def compute_id(
        detector: str,
        rule_id: str,
        file: str,
        line_start: int,
        sink_api: str,
    ) -> str:
        h = hashlib.sha256()
        h.update(f"{detector}|{rule_id}|{file}|{line_start}|{sink_api}".encode())
        return h.hexdigest()

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        # tuples -> lists for JSON
        d["cwe"] = list(self.cwe)
        d["sink"]["tainted_arg_indices"] = list(self.sink.tainted_arg_indices)
        d["taint_sources"] = [
            {
                "api_qualified_name": ts.api_qualified_name,
                **({"location": asdict(ts.location)} if ts.location else {}),
            }
            for ts in self.taint_sources
        ]
        # drop None fields for cleanliness
        return _strip_none(d)


def _strip_none(obj: Any) -> Any:
    if isinstance(obj, dict):
        return {k: _strip_none(v) for k, v in obj.items() if v is not None}
    if isinstance(obj, list):
        return [_strip_none(x) for x in obj]
    return obj


def validate_finding(payload: dict[str, Any]) -> None:
    """Raise :class:`jsonschema.ValidationError` if payload is invalid."""
    jsonschema.validate(payload, _SCHEMA)


def load_findings(path: str | Path) -> list[IRSAMFinding]:
    """Load a JSON-Lines file of findings (one IRSAMFinding per line)."""
    p = Path(path)
    findings: list[IRSAMFinding] = []
    with p.open(encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            payload = json.loads(line)
            validate_finding(payload)
            findings.append(_finding_from_dict(payload))
    return findings


def dedup_findings(findings: Iterable[IRSAMFinding]) -> list[IRSAMFinding]:
    """Collapse cross-detector duplicates by ``dedup_key`` (or computed key)."""
    seen: dict[str, IRSAMFinding] = {}
    for f in findings:
        key = f.dedup_key or _default_dedup_key(f)
        if key not in seen:
            seen[key] = f
    return list(seen.values())


def _default_dedup_key(f: IRSAMFinding) -> str:
    return f"{f.location.file}:{f.location.line_start}:{f.sink.api_qualified_name}"


def _finding_from_dict(p: dict[str, Any]) -> IRSAMFinding:
    loc = Location(**p["location"])
    sink = Sink(
        api_qualified_name=p["sink"]["api_qualified_name"],
        tainted_arg_indices=tuple(p["sink"]["tainted_arg_indices"]),
    )
    ts = tuple(
        TaintSource(
            api_qualified_name=t["api_qualified_name"],
            location=Location(**t["location"]) if t.get("location") else None,
        )
        for t in p.get("taint_sources", [])
    )
    ev = Evidence(**p["evidence"]) if p.get("evidence") else None
    return IRSAMFinding(
        finding_id=p["finding_id"],
        detector=p["detector"],
        detector_rule_id=p["detector_rule_id"],
        cwe=tuple(p["cwe"]),
        language=p["language"],
        interpreter=p["interpreter"],
        location=loc,
        sink=sink,
        schema_version=p.get("schema_version", "1.0.0"),
        detector_version=p.get("detector_version"),
        severity=p.get("severity"),
        taint_sources=ts,
        evidence=ev,
        confidence=p.get("confidence"),
        dedup_key=p.get("dedup_key"),
    )
