"""Schemas for scans / findings / patches / SARIF / PR."""

from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field


# --- Scans ---------------------------------------------------------------


class ScanCreate(BaseModel):
    trigger: Literal["manual", "api", "sarif"] = "manual"
    source_path: str | None = Field(
        default=None,
        description="Absolute path on the API host to scan (must live under "
                    "the workspace dir for safety).",
    )


class ScanOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: str
    project_id: str
    status: str
    trigger: str
    commit_sha: str | None
    started_at: datetime | None
    finished_at: datetime | None
    stats: dict[str, Any]
    created_at: datetime


# --- Findings ------------------------------------------------------------


class FindingStateUpdate(BaseModel):
    state: Literal["open", "dismissed", "wont_fix"]


# --- Patches -------------------------------------------------------------


class PatchDecision(BaseModel):
    status: Literal["approved", "rejected"]
    note: str | None = None


class OpenPRRequest(BaseModel):
    repo_owner: str
    repo_name: str
    base_branch: str = "main"
    token: str = Field(min_length=10, description="GitHub PAT with `repo` scope.")
    branch_prefix: str = "irsam/fix"
    title: str | None = None
    body: str | None = None


class PullRequestOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: str
    patch_proposal_id: str
    provider: str
    remote_id: str | None
    url: str | None
    status: str
    created_at: datetime


# --- SARIF ---------------------------------------------------------------


class SarifImportResponse(BaseModel):
    scan_id: str
    status: str
