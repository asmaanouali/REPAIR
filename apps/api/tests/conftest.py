"""Pytest fixtures: in-memory SQLite, settings overrides, async client."""

from __future__ import annotations

import os
import sys
from collections.abc import AsyncIterator
from pathlib import Path

import pytest
import pytest_asyncio


# Ensure ir-sam/ is on sys.path so `core.*` resolves the same way as the
# top-level tests/conftest.py does.
ROOT = Path(__file__).resolve().parents[3] / "ir-sam"
sys.path.insert(0, str(ROOT))

# Force a fully self-contained test environment BEFORE any irsam_api import.
# Use ``os.environ[...] = ...`` (not setdefault) so a polluted shell session
# can never leak credentials into the tests.
os.environ["IRSAM_DATABASE_URL"] = "sqlite+aiosqlite:///:memory:"
os.environ["IRSAM_JWT_SECRET"] = "test-secret-test-secret-test-secret"
os.environ["IRSAM_OWNER_EMAIL"] = "owner@example.com"
os.environ["IRSAM_OWNER_PASSWORD"] = "owner-password-123"
os.environ["IRSAM_SECRETS_FERNET_KEY"] = (
    "X1uXOnz5wMm7M8u5kE5p7P0t8eF7Q3K1Q5gV9R2W3aE="
)
os.environ["IRSAM_ENV"] = "test"
os.environ["IRSAM_LOG_LEVEL"] = "WARNING"
# Run background tasks in-process during tests (no Redis required).
os.environ["IRSAM_QUEUE_BACKEND"] = "inline"


from httpx import ASGITransport, AsyncClient  # noqa: E402

from irsam_api.bootstrap import create_schema, seed_owner  # noqa: E402
from irsam_api.db import dispose_engine  # noqa: E402
from irsam_api.main import create_app  # noqa: E402
from irsam_api.rate_limit import limiter  # noqa: E402
from irsam_api.settings import get_settings  # noqa: E402


@pytest_asyncio.fixture
async def app() -> AsyncIterator:
    settings = get_settings()
    await create_schema()
    await seed_owner(settings)
    limiter.reset()
    application = create_app()
    yield application
    await dispose_engine()


@pytest_asyncio.fixture
async def client(app) -> AsyncIterator[AsyncClient]:  # noqa: ANN001
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as c:
        yield c


@pytest.fixture
def owner_credentials() -> dict[str, str]:
    return {"email": "owner@example.com", "password": "owner-password-123"}


@pytest_asyncio.fixture
async def authed(client: AsyncClient, owner_credentials: dict[str, str]) -> AsyncClient:
    r = await client.post("/auth/login", json=owner_credentials)
    assert r.status_code == 200, r.text
    return client
