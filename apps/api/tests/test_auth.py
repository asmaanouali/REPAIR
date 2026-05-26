from __future__ import annotations

from httpx import AsyncClient


async def test_health_is_public(client: AsyncClient) -> None:
    r = await client.get("/health")
    assert r.status_code == 200
    body = r.json()
    assert body["status"] == "ok"
    assert body["env"] == "test"


async def test_login_sets_cookie_and_me_returns_user(
    client: AsyncClient, owner_credentials: dict[str, str]
) -> None:
    r = await client.post("/auth/login", json=owner_credentials)
    assert r.status_code == 200, r.text
    assert "irsam_session" in r.cookies

    me = await client.get("/auth/me")
    assert me.status_code == 200
    assert me.json()["email"] == owner_credentials["email"]


async def test_login_rejects_bad_password(client: AsyncClient) -> None:
    r = await client.post(
        "/auth/login",
        json={"email": "owner@example.com", "password": "wrong"},
    )
    assert r.status_code == 401


async def test_me_requires_auth(client: AsyncClient) -> None:
    r = await client.get("/auth/me")
    assert r.status_code == 401


async def test_logout_clears_cookie(authed: AsyncClient) -> None:
    r = await authed.post("/auth/logout")
    assert r.status_code == 204
    # After logout the cookie is unset; /auth/me must 401.
    authed.cookies.clear()
    r2 = await authed.get("/auth/me")
    assert r2.status_code == 401
