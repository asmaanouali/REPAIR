"""Runtime configuration loaded from environment variables / .env files."""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path
from typing import Literal

from pydantic import Field, SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict

# Resolve .env paths relative to this file's directory so they are found
# regardless of the cwd from which uvicorn/pytest is launched.
# __file__ = apps/api/src/irsam_api/settings.py → .parent.parent.parent = apps/api/
_APP_ROOT = Path(__file__).parent.parent.parent
_ENV_FILES = (
    str(_APP_ROOT / ".env"),
    str(_APP_ROOT / ".env.local"),
    ".env",
    ".env.local",
)


class Settings(BaseSettings):
    """Application settings.

    All env vars are prefixed with ``IRSAM_`` to avoid collisions
    when multiple services share a single environment file.
    """

    model_config = SettingsConfigDict(
        env_prefix="IRSAM_",
        env_file=_ENV_FILES,
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # General -----------------------------------------------------------------
    env: Literal["dev", "test", "prod"] = "dev"
    log_level: Literal["DEBUG", "INFO", "WARNING", "ERROR"] = "INFO"

    # HTTP --------------------------------------------------------------------
    host: str = "0.0.0.0"
    port: int = 8000
    allowed_origins: list[str] = Field(default_factory=lambda: ["http://localhost:3000"])
    api_root_path: str = ""

    # Auth --------------------------------------------------------------------
    jwt_secret: SecretStr = SecretStr("change-me-in-production")
    jwt_algorithm: str = "HS256"
    jwt_ttl_minutes: int = 60 * 12  # 12h
    cookie_name: str = "irsam_session"
    cookie_secure: bool = False  # set True behind TLS
    cookie_samesite: Literal["lax", "strict", "none"] = "lax"

    # Seeded owner ------------------------------------------------------------
    owner_email: str = "owner@local"
    owner_password: SecretStr = SecretStr("change-me-immediately")

    # Database / queue --------------------------------------------------------
    database_url: str = "postgresql+asyncpg://irsam:irsam@localhost:5432/irsam"
    redis_url: str = "redis://localhost:6379/0"

    # Secrets encryption (Fernet, 32-byte url-safe base64) --------------------
    # Generate with: python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
    secrets_fernet_key: SecretStr = SecretStr(
        "ZmFrZS1mZXJuZXQta2V5LXJlcGxhY2UtbWUtaW4tcHJvZHV4dD0="
    )

    # Scan workspace ----------------------------------------------------------
    workspace_dir: Path = Path("/tmp/irsam/workspace")

    # GitHub integration ------------------------------------------------------
    github_api_base: str = "https://api.github.com"


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Cached settings accessor."""
    return Settings()
