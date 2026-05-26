"""Authentication routes (login / logout / me)."""

from __future__ import annotations

from fastapi import APIRouter, HTTPException, Request, Response, status
from sqlalchemy import select

from .. import audit
from ..deps import CurrentUser, DBSession, SettingsDep
from ..models import User
from ..rate_limit import limiter
from ..schemas import LoginRequest, UserOut
from ..security import create_access_token, verify_password

router = APIRouter(prefix="/auth", tags=["auth"])


def _set_cookie(response: Response, token: str, settings) -> None:
    response.set_cookie(
        key=settings.cookie_name,
        value=token,
        httponly=True,
        secure=settings.cookie_secure,
        samesite=settings.cookie_samesite,
        max_age=settings.jwt_ttl_minutes * 60,
        path="/",
    )


@router.post("/login", response_model=UserOut)
@limiter.limit("10/minute")
async def login(
    request: Request,
    body: LoginRequest,
    response: Response,
    settings: SettingsDep,
    session: DBSession,
) -> UserOut:
    user = (await session.execute(
        select(User).where(User.email == body.email))).scalar_one_or_none()
    if user is None or not verify_password(body.password, user.password_hash):
        await audit.record(session, actor_id=None, action="auth.login_failed",
                            payload={"email": body.email})
        await session.commit()
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "invalid credentials")
    token = create_access_token(settings, subject=user.id,
                                 extra_claims={"role": user.role})
    _set_cookie(response, token, settings)
    await audit.record(session, actor_id=user.id, action="auth.login_succeeded",
                        target_type="user", target_id=user.id)
    await session.commit()
    return UserOut.model_validate(user)


@router.post("/logout", status_code=status.HTTP_204_NO_CONTENT)
async def logout(response: Response, settings: SettingsDep) -> Response:
    response.delete_cookie(settings.cookie_name, path="/")
    response.status_code = status.HTTP_204_NO_CONTENT
    return response


@router.get("/me", response_model=UserOut)
async def me(user: CurrentUser) -> UserOut:
    return UserOut.model_validate(user)
