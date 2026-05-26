"""Scan lifecycle endpoints + Server-Sent Events stream."""

from __future__ import annotations

import asyncio
import json
from typing import AsyncIterator

from fastapi import APIRouter, HTTPException, status
from fastapi.responses import StreamingResponse
from sqlalchemy import select

from ..deps import CurrentUser, DBSession
from ..logging_config import get_logger
from ..models import Finding, Project, Scan
from ..queue import enqueue
from ..schemas_ext import ScanCreate, ScanOut
from ..schemas import FindingOut

log = get_logger(__name__)
router = APIRouter(tags=["scans"])


async def _get_project(session, project_id: str, user_id: str) -> Project:
    proj = (await session.execute(
        select(Project).where(Project.id == project_id,
                              Project.owner_id == user_id))).scalar_one_or_none()
    if proj is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND,
                            detail="project_not_found")
    return proj


async def _get_scan(session, scan_id: str, user_id: str) -> Scan:
    scan = (await session.execute(
        select(Scan).where(Scan.id == scan_id))).scalar_one_or_none()
    if scan is None:
        raise HTTPException(status_code=404, detail="scan_not_found")
    # Authorisation: scan must belong to a project owned by the caller.
    proj = (await session.execute(
        select(Project).where(Project.id == scan.project_id,
                              Project.owner_id == user_id))).scalar_one_or_none()
    if proj is None:
        raise HTTPException(status_code=404, detail="scan_not_found")
    return scan


@router.post("/projects/{project_id}/scans", response_model=ScanOut,
             status_code=status.HTTP_201_CREATED)
async def create_scan(project_id: str, payload: ScanCreate,
                       user: CurrentUser, session: DBSession) -> Scan:
    proj = await _get_project(session, project_id, user.id)
    if not payload.source_path and proj.source_type == "git" and not proj.git_url:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                            detail="git_url_required")
    scan = Scan(project_id=proj.id, status="queued", trigger=payload.trigger)
    session.add(scan)
    await session.commit()
    await session.refresh(scan)
    if payload.source_path:
        await enqueue("run_scan", scan.id, payload.source_path)
    elif proj.source_type == "git" and proj.git_url:
        await enqueue("run_git_scan", scan.id, proj.git_url, proj.default_branch)
    return scan


@router.get("/projects/{project_id}/scans", response_model=list[ScanOut])
async def list_scans(project_id: str, user: CurrentUser,
                      session: DBSession) -> list[Scan]:
    await _get_project(session, project_id, user.id)
    rows = (await session.execute(
        select(Scan).where(Scan.project_id == project_id)
        .order_by(Scan.created_at.desc()))).scalars().all()
    return list(rows)


@router.get("/scans/{scan_id}", response_model=ScanOut)
async def get_scan(scan_id: str, user: CurrentUser, session: DBSession) -> Scan:
    return await _get_scan(session, scan_id, user.id)


@router.get("/scans/{scan_id}/findings", response_model=list[FindingOut])
async def list_findings(scan_id: str, user: CurrentUser,
                         session: DBSession) -> list[Finding]:
    await _get_scan(session, scan_id, user.id)
    rows = (await session.execute(
        select(Finding).where(Finding.scan_id == scan_id)
        .order_by(Finding.created_at.asc()))).scalars().all()
    return list(rows)


# ---------------------------------------------------------------------------
# Server-Sent Events: poll the scan row and stream status transitions.
# ---------------------------------------------------------------------------


async def _scan_event_stream(scan_id: str, user_id: str) -> AsyncIterator[bytes]:
    from ..db import get_session_factory
    factory = get_session_factory()
    last_payload: str | None = None
    for _ in range(600):  # ~10 min max stream
        async with factory() as session:
            try:
                scan = await _get_scan(session, scan_id, user_id)
            except HTTPException:
                yield b"event: error\ndata: scan_not_found\n\n"
                return
            payload = json.dumps({
                "id": scan.id,
                "status": scan.status,
                "stats": scan.stats,
            }, default=str)
        if payload != last_payload:
            yield f"data: {payload}\n\n".encode("utf-8")
            last_payload = payload
        if scan.status in {"succeeded", "failed", "cancelled"}:
            return
        await asyncio.sleep(1.0)


@router.get("/scans/{scan_id}/events")
async def scan_events(scan_id: str, user: CurrentUser,
                       session: DBSession) -> StreamingResponse:
    # Validate access once up-front so we surface 404s eagerly.
    await _get_scan(session, scan_id, user.id)
    return StreamingResponse(_scan_event_stream(scan_id, user.id),
                              media_type="text/event-stream")
