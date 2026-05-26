"""Projects CRUD."""

from __future__ import annotations

from fastapi import APIRouter, HTTPException, status
from sqlalchemy import select

from .. import audit
from ..deps import CurrentUser, DBSession
from ..models import Project
from ..schemas import ProjectCreate, ProjectOut, ProjectUpdate

router = APIRouter(prefix="/projects", tags=["projects"])


@router.get("", response_model=list[ProjectOut])
async def list_projects(user: CurrentUser, session: DBSession) -> list[ProjectOut]:
    rows = (await session.execute(
        select(Project).where(Project.owner_id == user.id)
                       .order_by(Project.created_at.desc()))
    ).scalars().all()
    return [ProjectOut.model_validate(p) for p in rows]


@router.post("", response_model=ProjectOut, status_code=status.HTTP_201_CREATED)
async def create_project(body: ProjectCreate, user: CurrentUser,
                          session: DBSession) -> ProjectOut:
    project = Project(
        owner_id=user.id, name=body.name, source_type=body.source_type,
        git_url=body.git_url, default_branch=body.default_branch,
        settings=body.settings,
    )
    session.add(project)
    await session.flush()
    await audit.record(session, actor_id=user.id, action="project.created",
                        target_type="project", target_id=project.id,
                        payload={"name": project.name, "source_type": project.source_type})
    await session.commit()
    await session.refresh(project)
    return ProjectOut.model_validate(project)


async def _load(session, user, project_id: str) -> Project:
    row = (await session.execute(
        select(Project).where(Project.id == project_id,
                              Project.owner_id == user.id))).scalar_one_or_none()
    if row is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "project not found")
    return row


@router.get("/{project_id}", response_model=ProjectOut)
async def get_project(project_id: str, user: CurrentUser,
                       session: DBSession) -> ProjectOut:
    return ProjectOut.model_validate(await _load(session, user, project_id))


@router.patch("/{project_id}", response_model=ProjectOut)
async def update_project(project_id: str, body: ProjectUpdate,
                          user: CurrentUser, session: DBSession) -> ProjectOut:
    project = await _load(session, user, project_id)
    if body.name is not None:
        project.name = body.name
    if body.default_branch is not None:
        project.default_branch = body.default_branch
    if body.settings is not None:
        project.settings = body.settings
    await session.commit()
    await session.refresh(project)
    return ProjectOut.model_validate(project)


@router.delete("/{project_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_project(project_id: str, user: CurrentUser,
                          session: DBSession) -> None:
    project = await _load(session, user, project_id)
    await audit.record(session, actor_id=user.id, action="project.deleted",
                        target_type="project", target_id=project.id,
                        payload={"name": project.name})
    await session.delete(project)
    await session.commit()
