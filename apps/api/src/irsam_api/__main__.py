"""``python -m irsam_api`` entrypoint -> uvicorn."""

from __future__ import annotations

import uvicorn

from .settings import get_settings


def main() -> None:
    s = get_settings()
    uvicorn.run(
        "irsam_api.main:app",
        host=s.host,
        port=s.port,
        log_level=s.log_level.lower(),
        reload=s.env == "dev",
    )


if __name__ == "__main__":
    main()
