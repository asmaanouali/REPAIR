"""Health and metadata endpoints."""

from __future__ import annotations

from fastapi import APIRouter

from .. import __version__
from ..deps import SettingsDep
from ..schemas import HealthOut

router = APIRouter(tags=["meta"])


@router.get("/health", response_model=HealthOut)
async def health(settings: SettingsDep) -> HealthOut:
    return HealthOut(status="ok", version=__version__, env=settings.env)
