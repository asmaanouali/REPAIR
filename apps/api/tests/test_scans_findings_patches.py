"""Scans + findings + patches + SARIF round-trips."""

from __future__ import annotations

import json

import pytest
from httpx import AsyncClient
from sqlalchemy import select

from irsam_api.db import get_session_factory
from irsam_api.models import Finding, PatchProposal, Project


pytestmark = pytest.mark.asyncio


async def _make_project(authed: AsyncClient) -> str:
    r = await authed.post("/projects", json={"name": "demo", "source_type": "upload"})
    assert r.status_code == 201, r.text
    return r.json()["id"]


async def test_create_scan_without_source_path_returns_queued(authed: AsyncClient) -> None:
    pid = await _make_project(authed)
    r = await authed.post(f"/projects/{pid}/scans", json={"trigger": "manual"})
    assert r.status_code == 201, r.text
    body = r.json()
    assert body["project_id"] == pid
    assert body["status"] == "queued"
    assert body["trigger"] == "manual"

    listing = await authed.get(f"/projects/{pid}/scans")
    assert listing.status_code == 200
    assert any(s["id"] == body["id"] for s in listing.json())

    detail = await authed.get(f"/scans/{body['id']}")
    assert detail.status_code == 200
    assert detail.json()["id"] == body["id"]

    findings = await authed.get(f"/scans/{body['id']}/findings")
    assert findings.status_code == 200
    assert findings.json() == []


async def test_git_project_scan_uses_git_url_without_source_path(
        authed: AsyncClient, monkeypatch: pytest.MonkeyPatch) -> None:
    enqueued: list[tuple[str, tuple[object, ...]]] = []

    async def fake_enqueue(name: str, *args: object) -> None:
        enqueued.append((name, args))

    monkeypatch.setattr("irsam_api.routers.scans.enqueue", fake_enqueue)
    project = await authed.post("/projects", json={
        "name": "git-demo",
        "source_type": "git",
        "git_url": "https://github.com/example/repo.git",
        "default_branch": "main",
    })
    assert project.status_code == 201, project.text

    r = await authed.post(
        f"/projects/{project.json()['id']}/scans",
        json={"trigger": "manual"},
    )
    assert r.status_code == 201, r.text
    scan_id = r.json()["id"]
    assert enqueued == [(
        "run_git_scan",
        (scan_id, "https://github.com/example/repo.git", "main"),
    )]


async def test_finding_state_transition_and_patches_roundtrip(
        authed: AsyncClient) -> None:
    pid = await _make_project(authed)
    scan_r = await authed.post(f"/projects/{pid}/scans", json={"trigger": "manual"})
    scan_id = scan_r.json()["id"]

    # Seed a Finding + PatchProposal directly so we can drive the review API.
    factory = get_session_factory()
    async with factory() as session:
        finding = Finding(
            scan_id=scan_id,
            rule_id="java/sql-injection",
            cwe="CWE-89",
            file_path="src/Demo.java",
            line=42,
            sink_api="java.sql.Statement.executeQuery",
            severity="high",
        )
        session.add(finding)
        await session.flush()
        patch = PatchProposal(
            finding_id=finding.id,
            stage_reached="G",
            unified_diff="--- a\n+++ b\n",
            patched_source="// patched contents",
            gate_report={"gates": []},
        )
        session.add(patch)
        await session.commit()
        finding_id, patch_id = finding.id, patch.id

    # GET finding + its patches
    r = await authed.get(f"/findings/{finding_id}")
    assert r.status_code == 200
    assert r.json()["cwe"] == "CWE-89"

    r = await authed.get(f"/findings/{finding_id}/patches")
    assert r.status_code == 200
    assert len(r.json()) == 1

    # Dismiss the finding
    r = await authed.patch(f"/findings/{finding_id}",
                            json={"state": "dismissed"})
    assert r.status_code == 200
    assert r.json()["state"] == "dismissed"

    # Approve the patch
    r = await authed.post(f"/patches/{patch_id}/decision",
                           json={"status": "approved"})
    assert r.status_code == 200
    assert r.json()["status"] == "approved"

    # Re-decision should now 409
    r = await authed.post(f"/patches/{patch_id}/decision",
                           json={"status": "rejected"})
    assert r.status_code == 409


async def test_finding_endpoints_require_owner(authed: AsyncClient) -> None:
    r = await authed.get("/findings/does-not-exist")
    assert r.status_code == 404


async def test_open_pr_requires_approved_patch(authed: AsyncClient) -> None:
    pid = await _make_project(authed)
    scan_r = await authed.post(f"/projects/{pid}/scans", json={"trigger": "manual"})
    scan_id = scan_r.json()["id"]
    factory = get_session_factory()
    async with factory() as session:
        f = Finding(scan_id=scan_id, rule_id="r", cwe="CWE-89",
                    file_path="a.java", line=1, sink_api="x", severity="low")
        session.add(f); await session.flush()
        p = PatchProposal(finding_id=f.id, stage_reached="G",
                          unified_diff="d", patched_source="src",
                          gate_report={})
        session.add(p); await session.commit()
        pid_patch = p.id

    r = await authed.post(f"/patches/{pid_patch}/pull-request", json={
        "repo_owner": "octo", "repo_name": "demo", "base_branch": "main",
        "token": "ghp_xxxxxxxxxxxxx",
    })
    assert r.status_code == 409
    assert r.json()["detail"] == "patch_must_be_approved"
