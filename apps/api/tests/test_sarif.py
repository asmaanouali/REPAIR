"""SARIF upload happy-path with a minimal CodeQL document."""

from __future__ import annotations

import asyncio
import json

import pytest
from httpx import AsyncClient
from sqlalchemy import select

from irsam_api.db import get_session_factory
from irsam_api.models import Finding


pytestmark = pytest.mark.asyncio


MINIMAL_CODEQL_SARIF = {
    "version": "2.1.0",
    "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
    "runs": [{
        "tool": {"driver": {"name": "CodeQL", "rules": [
            {"id": "java/sql-injection",
             "properties": {"tags": ["external/cwe/cwe-089"]}}
        ]}},
        "results": [{
            "ruleId": "java/sql-injection",
            "message": {"text": "User input flows into JDBC query."},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": "src/Demo.java"},
                    "region": {"startLine": 17, "endLine": 17}
                }
            }],
        }],
    }],
}


async def _make_project(authed: AsyncClient) -> str:
    r = await authed.post("/projects", json={"name": "demo",
                                              "source_type": "sarif"})
    return r.json()["id"]


async def test_sarif_upload_creates_scan_and_findings(
        authed: AsyncClient) -> None:
    pid = await _make_project(authed)
    blob = json.dumps(MINIMAL_CODEQL_SARIF).encode("utf-8")
    r = await authed.post(
        f"/projects/{pid}/sarif",
        files={"file": ("scan.sarif", blob, "application/sarif+json")},
    )
    assert r.status_code == 202, r.text
    scan_id = r.json()["scan_id"]

    # The inline queue schedules the task; give it a tick.
    for _ in range(20):
        await asyncio.sleep(0.05)
        factory = get_session_factory()
        async with factory() as session:
            rows = (await session.execute(
                select(Finding).where(Finding.scan_id == scan_id)
            )).scalars().all()
        if rows:
            break
    assert rows, "import_sarif_task should have created at least one finding"
    assert rows[0].rule_id == "java/sql-injection"
    assert rows[0].cwe == "CWE-89"


async def test_sarif_upload_empty_file_returns_422(authed: AsyncClient) -> None:
    pid = await _make_project(authed)
    r = await authed.post(
        f"/projects/{pid}/sarif",
        files={"file": ("empty.sarif", b"", "application/sarif+json")},
    )
    assert r.status_code == 422
