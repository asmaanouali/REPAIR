"""Schema bootstrap helpers.

For Phase 1 the bootstrap simply calls ``Base.metadata.create_all``
so the app, tests, and Docker Compose come up without requiring an
Alembic upgrade. Phase 2 swaps this for an explicit migration step
once the schema starts evolving.
"""

from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from .db import Base, get_engine, get_session_factory
from .logging_config import get_logger
from .models import User
from .security import hash_password
from .settings import Settings

log = get_logger(__name__)


async def create_schema() -> None:
    engine = get_engine()
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)


async def seed_owner(settings: Settings) -> None:
    factory = get_session_factory()
    async with factory() as session:  # type: AsyncSession
        existing = (await session.execute(
            select(User).where(User.email == settings.owner_email))).scalar_one_or_none()
        if existing is not None:
            return
        user = User(
            email=settings.owner_email,
            password_hash=hash_password(settings.owner_password.get_secret_value()),
            role="owner",
        )
        session.add(user)
        await session.commit()
        log.info("owner_seeded", email=settings.owner_email)


async def bootstrap(settings: Settings) -> None:
    await create_schema()
    await seed_owner(settings)
