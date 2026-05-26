"""FastAPI application factory."""

from __future__ import annotations

from contextlib import asynccontextmanager
from collections.abc import AsyncIterator

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded

from . import __version__
from .bootstrap import bootstrap
from .db import dispose_engine
from .logging_config import configure_logging, get_logger
from .middleware import OriginGuardMiddleware, SecurityHeadersMiddleware
from .queue import dispose as dispose_queue
from .rate_limit import limiter
from .routers import (
    auth, findings, health, patches, projects, quickfix, sarif, scans,
)
from .settings import get_settings


def create_app() -> FastAPI:
    settings = get_settings()
    configure_logging(settings.log_level)
    log = get_logger(__name__)

    @asynccontextmanager
    async def lifespan(_: FastAPI) -> AsyncIterator[None]:
        log.info("startup", env=settings.env, version=__version__)
        await bootstrap(settings)
        try:
            yield
        finally:
            await dispose_queue()
            await dispose_engine()
            log.info("shutdown")

    app = FastAPI(
        title="IR-SAM API",
        version=__version__,
        root_path=settings.api_root_path,
        lifespan=lifespan,
    )

    app.state.limiter = limiter
    app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

    app.add_middleware(SecurityHeadersMiddleware)
    app.add_middleware(
        OriginGuardMiddleware,
        allowed_origins=settings.allowed_origins,
        cookie_name=settings.cookie_name,
    )
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.allowed_origins,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    app.include_router(health.router)
    app.include_router(auth.router)
    app.include_router(projects.router)
    app.include_router(quickfix.router)
    app.include_router(scans.router)
    app.include_router(findings.router)
    app.include_router(patches.router)
    app.include_router(sarif.router)

    return app


app = create_app()
