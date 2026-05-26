"""Thin GitHub REST client for PR creation.

Only the surface we actually use: forking is out of scope (the user must
own the repo or have write access). The client stores no state.
"""

from __future__ import annotations

import base64
from dataclasses import dataclass
from typing import Any

import httpx

from ..logging_config import get_logger
from ..settings import get_settings

log = get_logger(__name__)


@dataclass
class GitHubRepo:
    owner: str
    repo: str
    default_branch: str = "main"


class GitHubError(RuntimeError):
    pass


class GitHubClient:
    def __init__(self, token: str, base_url: str | None = None) -> None:
        self.base_url = (base_url or get_settings().github_api_base).rstrip("/")
        self._headers = {
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "irsam-api",
        }

    async def _request(self, method: str, path: str, **kw: Any) -> httpx.Response:
        async with httpx.AsyncClient(timeout=20.0) as client:
            resp = await client.request(method, f"{self.base_url}{path}",
                                         headers=self._headers, **kw)
        if resp.status_code >= 400:
            raise GitHubError(f"{method} {path} -> {resp.status_code}: {resp.text}")
        return resp

    async def get_default_branch_sha(self, repo: GitHubRepo) -> str:
        r = await self._request("GET",
            f"/repos/{repo.owner}/{repo.repo}/git/refs/heads/{repo.default_branch}")
        return r.json()["object"]["sha"]

    async def create_branch(self, repo: GitHubRepo, branch: str, sha: str) -> None:
        await self._request("POST",
            f"/repos/{repo.owner}/{repo.repo}/git/refs",
            json={"ref": f"refs/heads/{branch}", "sha": sha})

    async def put_file(self, repo: GitHubRepo, branch: str, path: str,
                       content: str, message: str) -> None:
        # Look up existing SHA (if any) so we can update in place.
        sha: str | None = None
        try:
            r = await self._request("GET",
                f"/repos/{repo.owner}/{repo.repo}/contents/{path}",
                params={"ref": branch})
            sha = r.json().get("sha")
        except GitHubError:
            sha = None
        payload: dict[str, Any] = {
            "message": message,
            "content": base64.b64encode(content.encode("utf-8")).decode("ascii"),
            "branch": branch,
        }
        if sha:
            payload["sha"] = sha
        await self._request("PUT",
            f"/repos/{repo.owner}/{repo.repo}/contents/{path}", json=payload)

    async def open_pr(self, repo: GitHubRepo, branch: str, title: str,
                      body: str) -> dict[str, Any]:
        r = await self._request("POST",
            f"/repos/{repo.owner}/{repo.repo}/pulls",
            json={"title": title, "head": branch, "base": repo.default_branch,
                  "body": body, "draft": True})
        return r.json()


async def open_pull_request(*, token: str, repo: GitHubRepo, branch: str,
                            files: dict[str, str], title: str,
                            body: str) -> dict[str, Any]:
    """Create branch, commit ``files`` (path -> patched contents), open PR."""
    gh = GitHubClient(token)
    base_sha = await gh.get_default_branch_sha(repo)
    await gh.create_branch(repo, branch, base_sha)
    for path, content in files.items():
        await gh.put_file(repo, branch, path, content,
                           message=f"irsam: patch {path}")
    return await gh.open_pr(repo, branch, title, body)
