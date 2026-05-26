"""Arq tasks bridging the worker to ``core.api`` and the DB."""

from __future__ import annotations

import asyncio
import shutil
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from arq.connections import RedisSettings
from dulwich import porcelain
from dulwich.repo import Repo
from sqlalchemy import select

from core.api import (
    ScanOptions,
    generate_patch_for_file,
    import_sarif_bytes,
    run_scan_path,
)

from irsam_api.db import dispose_engine, get_session_factory
from irsam_api.logging_config import configure_logging, get_logger
from irsam_api.models import Finding, PatchProposal, Scan
from irsam_api.settings import get_settings

log = get_logger(__name__)


# ---------------------------------------------------------------------------
# Task implementations
# ---------------------------------------------------------------------------


async def _set_scan_status(scan_id: str, status: str, **fields: Any) -> None:
    factory = get_session_factory()
    async with factory() as session:
        scan = (await session.execute(
            select(Scan).where(Scan.id == scan_id))).scalar_one_or_none()
        if scan is None:
            log.warning("scan_missing", scan_id=scan_id)
            return
        scan.status = status
        for k, v in fields.items():
            setattr(scan, k, v)
        await session.commit()


async def run_scan(ctx: dict[str, Any], scan_id: str, root_path: str) -> dict[str, Any]:
    """Walk ``root_path``, persist findings + patches, return summary."""
    await _set_scan_status(scan_id, "running",
                           started_at=datetime.now(timezone.utc))
    factory = get_session_factory()
    summary: dict[str, Any] = {"files_examined": 0, "findings": 0, "patches": 0}
    try:
        # ``run_scan_path`` is a blocking iterator; offload to a thread so
        # the event loop stays responsive.
        loop = asyncio.get_running_loop()
        events = await loop.run_in_executor(
            None, lambda: list(run_scan_path(Path(root_path), ScanOptions(),
                                              scan_id=scan_id)))
        async with factory() as session:
            for ev in events:
                if ev.kind == "scan_finished":
                    record = ev.payload["record"]
                    summary = {
                        "files_examined": record["files_examined"],
                        "findings": len(record["findings"]),
                        "patches": len(record["patches"]),
                    }
                    for f in record["findings"]:
                        finding = Finding(
                            scan_id=scan_id,
                            rule_id=f["detector_rule_id"],
                            cwe=(f["cwe"][0] if f["cwe"] else "CWE-89"),
                            file_path=f["file"],
                            line=f["line_start"],
                            sink_api=f["sink_api"],
                            severity=f["severity"] or "medium",
                        )
                        session.add(finding)
                    await session.flush()
                    for p in record["patches"]:
                        proposal = PatchProposal(
                            finding_id=None,  # linked via separate matching pass
                            stage_reached=p["stage_reached"],
                            unified_diff=p["unified_diff"],
                            patched_source=p["patched_source"],
                            plan={
                                "prepared_template": p.get("prepared_template"),
                                "binders_used": p.get("binders_used", []),
                                "proof_status": p.get("proof_status", "unverified"),
                                "safety_claim": p.get("safety_claim", ""),
                                "abstention_reason": p.get("abstention_reason"),
                                "all_gates_passed": p.get("all_gates_passed", False),
                            },
                            gate_report={"gates": p["gates"]},
                        )
                        # finding_id is NOT NULL in schema; assign the most
                        # recent finding for the same file (best-effort link).
                        last = (await session.execute(
                            select(Finding).where(
                                Finding.scan_id == scan_id,
                                Finding.file_path == p["file"]
                            ).order_by(Finding.created_at.desc()))
                        ).scalars().first()
                        if last is None:
                            continue
                        proposal.finding_id = last.id
                        session.add(proposal)
            await session.commit()
        await _set_scan_status(
            scan_id, "succeeded",
            finished_at=datetime.now(timezone.utc),
            stats=summary,
        )
    except Exception as exc:  # noqa: BLE001 - boundary
        log.error("scan_failed", scan_id=scan_id, error=repr(exc))
        await _set_scan_status(scan_id, "failed",
                                finished_at=datetime.now(timezone.utc),
                                stats={"error": repr(exc)})
        raise
    return summary


def _clone_git_repo(git_url: str, branch: str | None, target: Path) -> str | None:
    parsed = urlparse(git_url)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise ValueError("unsupported_git_url")

    target.parent.mkdir(parents=True, exist_ok=True)
    if target.exists():
        shutil.rmtree(target)

    kwargs: dict[str, Any] = {"checkout": True, "depth": 1}
    if branch:
        kwargs["branch"] = branch.encode("utf-8")
    porcelain.clone(git_url, str(target), **kwargs)

    try:
        return Repo(str(target)).head().decode("ascii")
    except Exception:  # noqa: BLE001 - commit sha is useful but non-critical
        return None


async def run_git_scan(
    ctx: dict[str, Any],
    scan_id: str,
    git_url: str,
    branch: str | None = None,
) -> dict[str, Any]:
    """Clone ``git_url`` into the scan workspace, then run a normal scan."""
    settings = get_settings()
    checkout = settings.workspace_dir / "git" / scan_id
    await _set_scan_status(
        scan_id,
        "running",
        started_at=datetime.now(timezone.utc),
        stats={"phase": "cloning", "git_url": git_url, "branch": branch},
    )
    try:
        loop = asyncio.get_running_loop()
        commit_sha = await loop.run_in_executor(
            None, lambda: _clone_git_repo(git_url, branch, checkout)
        )
    except Exception as exc:  # noqa: BLE001 - boundary
        log.error("git_clone_failed", scan_id=scan_id, git_url=git_url,
                  branch=branch, error=repr(exc))
        await _set_scan_status(
            scan_id,
            "failed",
            finished_at=datetime.now(timezone.utc),
            stats={"error": repr(exc), "git_url": git_url, "branch": branch},
        )
        raise

    await _set_scan_status(
        scan_id,
        "running",
        commit_sha=commit_sha,
        stats={
            "phase": "scanning",
            "git_url": git_url,
            "branch": branch,
            "checkout": str(checkout),
        },
    )
    return await run_scan(ctx, scan_id, str(checkout))


async def generate_patch(ctx: dict[str, Any], finding_id: str,
                         file_path: str) -> dict[str, Any]:
    loop = asyncio.get_running_loop()
    record = await loop.run_in_executor(None, generate_patch_for_file, file_path)
    factory = get_session_factory()
    async with factory() as session:
        proposal = PatchProposal(
            finding_id=finding_id,
            stage_reached=record.stage_reached,
            unified_diff=record.unified_diff,
            patched_source=record.patched_source,
            plan={
                "prepared_template": record.prepared_template,
                "binders_used": list(record.binders_used),
                "proof_status": record.proof_status,
                "safety_claim": record.safety_claim,
                "abstention_reason": record.abstention_reason,
                "all_gates_passed": record.all_gates_passed,
            },
            gate_report={"gates": [g.__dict__ for g in record.gates]},
        )
        session.add(proposal)
        await session.commit()
    return {"finding_id": finding_id, "stage_reached": record.stage_reached}


async def import_sarif_task(ctx: dict[str, Any], scan_id: str,
                             blob_b64: str) -> dict[str, Any]:
    import base64
    loop = asyncio.get_running_loop()
    blob = base64.b64decode(blob_b64.encode("ascii"))
    findings = await loop.run_in_executor(None, import_sarif_bytes, blob)
    factory = get_session_factory()
    async with factory() as session:
        for f in findings:
            session.add(Finding(
                scan_id=scan_id,
                rule_id=f.detector_rule_id,
                cwe=(f.cwe[0] if f.cwe else "CWE-89"),
                file_path=f.file,
                line=f.line_start,
                sink_api=f.sink_api,
                severity=f.severity or "medium",
            ))
        await session.commit()
    await _set_scan_status(scan_id, "succeeded",
                            finished_at=datetime.now(timezone.utc),
                            stats={"findings": len(findings)})
    return {"scan_id": scan_id, "imported": len(findings)}


# ---------------------------------------------------------------------------
# Arq worker settings
# ---------------------------------------------------------------------------


async def _on_startup(ctx: dict[str, Any]) -> None:
    configure_logging(get_settings().log_level)
    log.info("worker_startup")


async def _on_shutdown(ctx: dict[str, Any]) -> None:
    await dispose_engine()
    log.info("worker_shutdown")


class WorkerSettings:
    functions = [run_scan, run_git_scan, generate_patch, import_sarif_task]
    on_startup = _on_startup
    on_shutdown = _on_shutdown
    redis_settings = RedisSettings.from_dsn(get_settings().redis_url)
    max_jobs = 4
    job_timeout = 60 * 30  # 30 min
