"""Serializable production artifacts shared across IR-SAM stages."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Literal

from core.ingest.unified import IRSAMFinding

StageName = Literal["A", "B", "C", "D", "E", "F", "G"]
StageStatus = Literal["pending", "running", "succeeded", "abstained", "failed"]


class AbstentionCode(str, Enum):
    """Canonical typed abstention reasons for production artifacts."""

    UNSUPPORTED_DIALECT = "UnsupportedDialect"
    AMBIGUOUS_INTENT = "AmbiguousIntent"
    IDENTIFIER_NOT_IN_DT = "IdentifierNotInDT"
    NO_CATALOG_MATCH = "NoCatalogMatch"
    BUILD_FAILURE = "BuildFailure"
    TEST_REGRESSION = "TestRegression"
    STRUCTURAL_CHECK_FAILED = "StructuralCheckFailed"
    RESIDUAL_SAST = "ResidualSAST"
    DIFFERENTIAL_DIVERGENCE = "DifferentialDivergence"
    UNSUPPORTED_LANGUAGE = "UnsupportedLanguage"
    UNSUPPORTED_FRAMEWORK = "UnsupportedFramework"
    FINDING_FILE_NOT_FOUND = "FindingFileNotFound"
    NO_SINK_FOUND = "NoSinkFound"
    SLICE_UNSUPPORTED = "SliceUnsupported"
    PARSE_ERROR = "ParseError"
    REWRITE_UNSUPPORTED = "RewriteUnsupported"
    INTERNAL_ERROR = "InternalError"


def resolve_finding_path(project_root: str | Path, finding: IRSAMFinding) -> Path:
    """Resolve a finding file URI/path against a project root."""
    raw = Path(finding.location.file)
    if raw.is_absolute():
        return raw
    return Path(project_root).resolve() / raw


def stable_artifact_id(project_root: str | Path, finding: IRSAMFinding) -> str:
    """Return a stable artifact prefix for all outputs from one finding."""
    source = resolve_finding_path(project_root, finding)
    digest = hashlib.sha256(
        "|".join(
            (
                finding.finding_id,
                finding.detector,
                finding.detector_rule_id,
                source.as_posix(),
                str(finding.location.line_start),
                finding.sink.api_qualified_name,
            )
        ).encode("utf-8")
    ).hexdigest()
    return f"irsam-{digest[:24]}"


@dataclass(frozen=True)
class PipelineJob:
    """One scheduled IR-SAM job for one normalized detector finding."""

    project_root: str
    finding: IRSAMFinding
    source_path: str
    job_id: str
    artifact_id: str

    @classmethod
    def from_finding(
        cls, project_root: str | Path, finding: IRSAMFinding
    ) -> "PipelineJob":
        root = Path(project_root).resolve()
        source_path = resolve_finding_path(root, finding)
        artifact_id = stable_artifact_id(root, finding)
        job_digest = hashlib.sha256(
            f"{artifact_id}|{finding.finding_id}".encode("utf-8")
        ).hexdigest()
        return cls(
            project_root=str(root),
            finding=finding,
            source_path=str(source_path),
            job_id=job_digest[:32],
            artifact_id=artifact_id,
        )

    def to_metadata(self) -> dict[str, Any]:
        return {
            "job_id": self.job_id,
            "artifact_id": self.artifact_id,
            "finding_id": self.finding.finding_id,
            "detector": self.finding.detector,
            "detector_rule_id": self.finding.detector_rule_id,
            "language": self.finding.language,
            "interpreter": self.finding.interpreter,
            "source_path": self.source_path,
            "sink_api": self.finding.sink.api_qualified_name,
        }


@dataclass(frozen=True)
class StageCheckpoint:
    """Machine-readable checkpoint emitted after a stage transition."""

    job_id: str
    finding_id: str
    stage: StageName
    status: StageStatus
    artifact_id: str
    reason: str | None = None
    abstention_code: AbstentionCode | None = None
    artifact_refs: tuple[str, ...] = ()
    details: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "job_id": self.job_id,
            "finding_id": self.finding_id,
            "stage": self.stage,
            "status": self.status,
            "artifact_id": self.artifact_id,
            "reason": self.reason,
            "abstention_code": (
                self.abstention_code.value if self.abstention_code else None
            ),
            "artifact_refs": list(self.artifact_refs),
            "details": self.details,
        }


@dataclass(frozen=True)
class AbstentionArtifact:
    """Serializable abstention record for failed or unsupported jobs."""

    job_id: str
    finding_id: str
    artifact_id: str
    stage: StageName
    code: AbstentionCode
    reason: str
    file: str
    line_start: int | None = None
    details: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "job_id": self.job_id,
            "finding_id": self.finding_id,
            "artifact_id": self.artifact_id,
            "stage": self.stage,
            "code": self.code.value,
            "reason": self.reason,
            "file": self.file,
            "line_start": self.line_start,
            "details": self.details,
        }


def abstention_code_from_reason(
    stage: str, reason: str | None
) -> AbstentionCode | None:
    """Map legacy stage strings to the canonical abstention vocabulary."""
    if reason is None:
        return None
    lowered = reason.lower()
    if "unsupported_backend" in lowered:
        return AbstentionCode.UNSUPPORTED_LANGUAGE
    if "finding_file_not_found" in lowered:
        return AbstentionCode.FINDING_FILE_NOT_FOUND
    if "no_sink_found" in lowered:
        return AbstentionCode.NO_SINK_FOUND
    if "ambiguous_intent" in lowered:
        return AbstentionCode.AMBIGUOUS_INTENT
    if "identifier" in lowered and ("allow" in lowered or "dt" in lowered):
        return AbstentionCode.IDENTIFIER_NOT_IN_DT
    if "no_catalog" in lowered or "no_binder" in lowered:
        return AbstentionCode.NO_CATALOG_MATCH
    if "sql0_syntax" in lowered or "parse" in lowered:
        return AbstentionCode.PARSE_ERROR
    if "compile" in lowered or "build" in lowered:
        return AbstentionCode.BUILD_FAILURE
    if "regression" in lowered or "test" in lowered:
        return AbstentionCode.TEST_REGRESSION
    if "structural" in lowered:
        return AbstentionCode.STRUCTURAL_CHECK_FAILED
    if "sast" in lowered:
        return AbstentionCode.RESIDUAL_SAST
    if "differential" in lowered or "oracle" in lowered:
        return AbstentionCode.DIFFERENTIAL_DIVERGENCE
    if stage == "B":
        return AbstentionCode.SLICE_UNSUPPORTED
    if stage == "F":
        return AbstentionCode.REWRITE_UNSUPPORTED
    return AbstentionCode.INTERNAL_ERROR