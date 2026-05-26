from __future__ import annotations

from httpx import AsyncClient


VULN_JAVA = """\
public class Sample {
    public void f(java.sql.Connection conn, String name) throws Exception {
        java.sql.Statement stmt = conn.createStatement();
        String sql = "SELECT * FROM users WHERE name = '" + name + "'";
        stmt.executeQuery(sql);
    }
}
"""


async def test_quickfix_requires_auth(client: AsyncClient) -> None:
    r = await client.post("/quickfix", json={"source": "x", "language": "java"})
    assert r.status_code == 401


async def test_quickfix_returns_patch_record(authed: AsyncClient) -> None:
    r = await authed.post(
        "/quickfix",
        json={"source": VULN_JAVA, "language": "java"},
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["language"] == "java"
    assert body["result"]["stage_reached"] in {"D", "E", "F", "G"}
    assert isinstance(body["result"]["gates"], list)
