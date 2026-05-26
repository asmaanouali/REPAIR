"""Pydantic v2 request/response schemas."""

from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, EmailStr, Field


# --- Auth ----------------------------------------------------------------


class LoginRequest(BaseModel):
    email: EmailStr
    password: str = Field(min_length=1, max_length=256)


class UserOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: str
    email: str
    role: str
    created_at: datetime


# --- Projects ------------------------------------------------------------


class ProjectCreate(BaseModel):
    name: str = Field(min_length=1, max_length=255)
    source_type: Literal["upload", "git", "sarif"] = "upload"
    git_url: str | None = None
    default_branch: str | None = "main"
    settings: dict[str, Any] = Field(default_factory=dict)


class ProjectUpdate(BaseModel):
    name: str | None = None
    default_branch: str | None = None
    settings: dict[str, Any] | None = None


class ProjectOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: str
    owner_id: str
    name: str
    source_type: str
    git_url: str | None
    default_branch: str | None
    settings: dict[str, Any]
    created_at: datetime


# --- Quickfix ------------------------------------------------------------


class QuickfixRequest(BaseModel):
    source: str = Field(min_length=1, max_length=512 * 1024)
    language: Literal["java", "python"] = "java"
    allowlists: dict[str, str] = Field(default_factory=dict)


class GateOut(BaseModel):
    name: str
    passed: bool
    detail: str = ""


class PatchOut(BaseModel):
    file: str
    stage_reached: str
    patched: bool
    all_gates_passed: bool
    abstention_reason: str | None
    unified_diff: str | None
    patched_source: str | None
    prepared_template: str | None
    binders_used: list[str]
    gates: list[GateOut]


class QuickfixResponse(BaseModel):
    request_id: str
    language: str
    elapsed_ms: int
    result: PatchOut


# --- Findings / Patches --------------------------------------------------


class FindingOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: str
    scan_id: str
    rule_id: str
    cwe: str
    file_path: str
    line: int
    sink_api: str
    severity: str
    state: str
    created_at: datetime


class PatchProposalOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: str
    finding_id: str
    stage_reached: str
    unified_diff: str | None
    status: str
    decided_at: datetime | None
    created_at: datetime
    plan: dict | None = None
    gate_report: dict | None = None


# --- Common --------------------------------------------------------------


class HealthOut(BaseModel):
    status: Literal["ok"] = "ok"
    version: str
    env: str
