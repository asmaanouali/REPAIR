from __future__ import annotations

from httpx import AsyncClient


async def test_projects_requires_auth(client: AsyncClient) -> None:
    r = await client.get("/projects")
    assert r.status_code == 401


async def test_project_crud_round_trip(authed: AsyncClient) -> None:
    r = await authed.post("/projects",
                          json={"name": "demo", "source_type": "upload"})
    assert r.status_code == 201, r.text
    project = r.json()
    assert project["name"] == "demo"
    pid = project["id"]

    r = await authed.get("/projects")
    assert r.status_code == 200
    assert any(p["id"] == pid for p in r.json())

    r = await authed.patch(f"/projects/{pid}", json={"name": "demo-renamed"})
    assert r.status_code == 200
    assert r.json()["name"] == "demo-renamed"

    r = await authed.delete(f"/projects/{pid}")
    assert r.status_code == 204
    r = await authed.get(f"/projects/{pid}")
    assert r.status_code == 404
