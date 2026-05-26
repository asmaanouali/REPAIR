"""Password hashing, JWT issuance/verification, secrets encryption."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any

import bcrypt
from cryptography.fernet import Fernet, InvalidToken
from jose import JWTError, jwt

from .settings import Settings


# bcrypt's hard limit is 72 bytes; truncate defensively to avoid runtime
# errors on long passwords while still being deterministic.
def _truncate(plain: str) -> bytes:
    return plain.encode("utf-8")[:72]


def hash_password(plain: str) -> str:
    return bcrypt.hashpw(_truncate(plain), bcrypt.gensalt()).decode("utf-8")


def verify_password(plain: str, hashed: str) -> bool:
    try:
        return bcrypt.checkpw(_truncate(plain), hashed.encode("utf-8"))
    except (ValueError, TypeError):
        return False


def create_access_token(settings: Settings, *, subject: str,
                        extra_claims: dict[str, Any] | None = None) -> str:
    now = datetime.now(timezone.utc)
    expires = now + timedelta(minutes=settings.jwt_ttl_minutes)
    payload: dict[str, Any] = {
        "sub": subject,
        "iat": int(now.timestamp()),
        "exp": int(expires.timestamp()),
    }
    if extra_claims:
        payload.update(extra_claims)
    return jwt.encode(payload, settings.jwt_secret.get_secret_value(),
                       algorithm=settings.jwt_algorithm)


def decode_access_token(settings: Settings, token: str) -> dict[str, Any] | None:
    try:
        return jwt.decode(token, settings.jwt_secret.get_secret_value(),
                          algorithms=[settings.jwt_algorithm])
    except JWTError:
        return None


def _fernet(settings: Settings) -> Fernet:
    return Fernet(settings.secrets_fernet_key.get_secret_value().encode())


def encrypt_secret(settings: Settings, plain: str) -> str:
    return _fernet(settings).encrypt(plain.encode("utf-8")).decode("utf-8")


def decrypt_secret(settings: Settings, token: str) -> str | None:
    try:
        return _fernet(settings).decrypt(token.encode("utf-8")).decode("utf-8")
    except (InvalidToken, ValueError):
        return None
