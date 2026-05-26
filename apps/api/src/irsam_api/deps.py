"""FastAPI dependencies for auth, DB session, settings."""

from __future__ import annotations

from typing import Annotated

from fastapi import Cookie, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from .db import get_session
from .models import User
from .security import decode_access_token
from .settings import Settings, get_settings


SettingsDep = Annotated[Settings, Depends(get_settings)]
DBSession = Annotated[AsyncSession, Depends(get_session)]


async def current_user(
    settings: SettingsDep,
    session: DBSession,
    session_cookie: Annotated[str | None, Cookie(alias="irsam_session")] = None,
) -> User:
    if not session_cookie:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "not authenticated")
    payload = decode_access_token(settings, session_cookie)
    if payload is None:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "invalid session")
    sub = payload.get("sub")
    if not sub:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "invalid session")
    user = (await session.execute(select(User).where(User.id == sub))).scalar_one_or_none()
    if user is None:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "user not found")
    return user


CurrentUser = Annotated[User, Depends(current_user)]
