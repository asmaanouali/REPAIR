"""Background job queue.

Two backends:

* ``arq`` (production): pushes jobs into Redis; consumed by ``apps/worker``.
* ``inline`` (tests / single-process dev): runs the task coroutine in the
  same event loop. We pick this automatically when Redis is unavailable
  or when ``IRSAM_QUEUE_BACKEND=inline``.

The queue exposes one verb — ``enqueue(name, *args)`` — that returns
nothing useful. Job results are persisted by the task itself (via the
DB), so the API just fires-and-forgets.
"""

from __future__ import annotations

import asyncio
import importlib
import os
from typing import Any

from arq import create_pool
from arq.connections import ArqRedis, RedisSettings

from .logging_config import get_logger
from .settings import get_settings

log = get_logger(__name__)

_pool: ArqRedis | None = None
_pool_lock = asyncio.Lock()


def _backend() -> str:
    explicit = os.environ.get("IRSAM_QUEUE_BACKEND")
    if explicit:
        return explicit
    return "arq"


async def _get_pool() -> ArqRedis | None:
    global _pool
    if _pool is not None:
        return _pool
    async with _pool_lock:
        if _pool is not None:
            return _pool
        try:
            _pool = await create_pool(
                RedisSettings.from_dsn(get_settings().redis_url))
        except Exception as exc:  # noqa: BLE001 - degrade gracefully
            log.warning("queue_redis_unavailable", error=repr(exc))
            return None
        return _pool


def _resolve_task(name: str):
    mod = importlib.import_module("irsam_worker.tasks")
    fn = getattr(mod, name, None)
    if fn is None:
        raise LookupError(f"unknown task: {name}")
    return fn


async def enqueue(name: str, *args: Any) -> None:
    """Submit a task by name. Falls back to inline execution if needed."""
    backend = _backend()
    if backend == "arq":
        pool = await _get_pool()
        if pool is not None:
            await pool.enqueue_job(name, *args)
            return
        # else fall through to inline
    fn = _resolve_task(name)
    # The worker tasks expect a ``ctx`` dict as first arg.
    coro = fn({}, *args)
    asyncio.create_task(coro)


async def dispose() -> None:
    global _pool
    if _pool is not None:
        await _pool.close()
        _pool = None
