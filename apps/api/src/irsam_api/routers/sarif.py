"""SARIF upload — create a scan + enqueue ingestion."""

from __future__ import annotations

import base64

from fastapi import APIRouter, File, HTTPException, UploadFile, status
from sqlalchemy import select

from ..deps import CurrentUser, DBSession
from ..models import Project, Scan
from ..queue import enqueue
from ..schemas_ext import SarifImportResponse

router = APIRouter(tags=["sarif"])

MAX_SARIF_BYTES = 25 * 1024 * 1024  # 25MB


@router.post("/projects/{project_id}/sarif", response_model=SarifImportResponse,
             status_code=status.HTTP_202_ACCEPTED)
async def import_sarif(project_id: str, user: CurrentUser, session: DBSession,
                        file: UploadFile = File(...)) -> SarifImportResponse:
    proj = (await session.execute(
        select(Project).where(Project.id == project_id,
                              Project.owner_id == user.id))).scalar_one_or_none()
    if proj is None:
        raise HTTPException(404, detail="project_not_found")
    blob = await file.read()
    if not blob:
        raise HTTPException(422, detail="empty_file")
    if len(blob) > MAX_SARIF_BYTES:
        raise HTTPException(413, detail="sarif_too_large")
    scan = Scan(project_id=proj.id, status="queued", trigger="sarif")
    session.add(scan)
    await session.commit()
    await session.refresh(scan)
    await enqueue("import_sarif_task", scan.id,
                   base64.b64encode(blob).decode("ascii"))
    return SarifImportResponse(scan_id=scan.id, status=scan.status)
