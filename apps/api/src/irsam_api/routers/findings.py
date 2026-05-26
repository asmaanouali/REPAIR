"""Findings: read + state transitions + on-demand patch regeneration."""

from __future__ import annotations

from datetime import datetime, timezone

from fastapi import APIRouter, HTTPException, status
from sqlalchemy import select

from ..deps import CurrentUser, DBSession
from ..models import Finding, PatchProposal, Project, Scan
from ..queue import enqueue
from ..schemas import FindingOut, PatchProposalOut
from ..schemas_ext import FindingStateUpdate

router = APIRouter(tags=["findings"])


async def _get_finding(session, finding_id: str, user_id: str) -> Finding:
    finding = (await session.execute(
        select(Finding).where(Finding.id == finding_id))).scalar_one_or_none()
    if finding is None:
        raise HTTPException(404, detail="finding_not_found")
    proj = (await session.execute(
        select(Project).join(Scan, Scan.project_id == Project.id)
        .where(Scan.id == finding.scan_id, Project.owner_id == user_id)
    )).scalar_one_or_none()
    if proj is None:
        raise HTTPException(404, detail="finding_not_found")
    return finding


@router.get("/findings/{finding_id}", response_model=FindingOut)
async def get_finding(finding_id: str, user: CurrentUser,
                       session: DBSession) -> Finding:
    return await _get_finding(session, finding_id, user.id)


@router.get("/findings/{finding_id}/patches",
            response_model=list[PatchProposalOut])
async def list_finding_patches(finding_id: str, user: CurrentUser,
                                session: DBSession) -> list[PatchProposal]:
    await _get_finding(session, finding_id, user.id)
    rows = (await session.execute(
        select(PatchProposal).where(PatchProposal.finding_id == finding_id)
        .order_by(PatchProposal.created_at.desc()))).scalars().all()
    return list(rows)


@router.patch("/findings/{finding_id}", response_model=FindingOut)
async def update_finding_state(finding_id: str, payload: FindingStateUpdate,
                                user: CurrentUser,
                                session: DBSession) -> Finding:
    finding = await _get_finding(session, finding_id, user.id)
    finding.state = payload.state
    await session.commit()
    await session.refresh(finding)
    return finding


@router.post("/findings/{finding_id}/regenerate-patch",
             status_code=status.HTTP_202_ACCEPTED)
async def regenerate_patch(finding_id: str, user: CurrentUser,
                            session: DBSession) -> dict[str, str]:
    finding = await _get_finding(session, finding_id, user.id)
    await enqueue("generate_patch", finding.id, finding.file_path)
    return {"status": "queued", "finding_id": finding.id}
