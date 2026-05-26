"""Audit logging helper.

Writes structured records to the ``audit_log`` table. Best-effort: failures
are swallowed (with a warning) so they never block the user-facing request.
"""

from __future__ import annotations

from typing import Any

from sqlalchemy.ext.asyncio import AsyncSession

from .logging_config import get_logger
from .models import AuditLog

log = get_logger(__name__)


async def record(
    session: AsyncSession,
    *,
    actor_id: str | None,
    action: str,
    target_type: str | None = None,
    target_id: str | None = None,
    payload: dict[str, Any] | None = None,
) -> None:
    """Persist an audit entry. Caller's transaction commits it."""
    try:
        session.add(AuditLog(
            actor_id=actor_id,
            action=action,
            target_type=target_type,
            target_id=target_id,
            payload=payload,
        ))
        await session.flush()
    except Exception as exc:  # pragma: no cover - audit must never break a request
        log.warning("audit_log_failed", action=action, error=str(exc))
