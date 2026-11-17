"""
SentinelRAG — Security and Cryptography Utilities.

Implements:
  - Argon2id password hashing and constant-time verification.
  - Secure token hashing (SHA-256) for refresh token storage.
  - JWT creation and validation with strict algorithm, issuer, and audience checks.
"""
from __future__ import annotations

import hashlib
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

import argon2
import jwt

from app.core.config import get_settings
from app.core.logging import get_logger

logger = get_logger(__name__)

# Argon2id password hasher instance
_hasher = argon2.PasswordHasher(
    time_cost=2,
    memory_cost=65536,  # 64 MB
    parallelism=2,
    hash_len=32,
    salt_len=16,
    type=argon2.Type.ID,
)


def hash_password(password: str) -> str:
    """Hash a plaintext password using Argon2id."""
    return _hasher.hash(password)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """
    Verify a plaintext password against an Argon2id hash.
    Returns True if valid, False otherwise.
    """
    try:
        return _hasher.verify(hashed_password, plain_password)
    except (argon2.exceptions.VerifyMismatchError, argon2.exceptions.VerificationError):
        return False
    except Exception as exc:  # noqa: BLE001
        logger.warning("Unexpected error during password verification", extra={"error": str(exc)})
        return False


def hash_token(token: str) -> str:
    """
    Compute a SHA-256 hash of a token.
    Used to store refresh tokens securely in MongoDB so that raw tokens are never persisted.
    """
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def create_access_token(
    user_id: str,
    email: str,
    role: str = "user",
    expires_delta: Optional[timedelta] = None,
) -> str:
    """
    Create a signed JWT access token.
    Claims include sub (user_id), email, role, token_type="access", iss, aud, exp, iat, jti.
    """
    settings = get_settings()
    now = datetime.now(timezone.utc)
    if expires_delta:
        expire = now + expires_delta
    else:
        expire = now + timedelta(minutes=settings.ACCESS_TOKEN_TTL_MINUTES)

    payload: dict[str, Any] = {
        "sub": user_id,
        "email": email,
        "role": role,
        "token_type": "access",
        "jti": str(uuid.uuid4()),
        "iss": settings.JWT_ISSUER,
        "aud": settings.JWT_AUDIENCE,
        "iat": int(now.timestamp()),
        "exp": int(expire.timestamp()),
    }

    return jwt.encode(payload, settings.JWT_SECRET, algorithm=settings.JWT_ALGORITHM)


def create_refresh_token(
    user_id: str,
    expires_delta: Optional[timedelta] = None,
) -> tuple[str, datetime]:
    """
    Create a signed JWT refresh token.
    Returns (raw_jwt_token, expires_at_datetime).
    """
    settings = get_settings()
    now = datetime.now(timezone.utc)
    if expires_delta:
        expire = now + expires_delta
    else:
        expire = now + timedelta(days=settings.REFRESH_TOKEN_TTL_DAYS)

    payload: dict[str, Any] = {
        "sub": user_id,
        "token_type": "refresh",
        "jti": str(uuid.uuid4()),
        "iss": settings.JWT_ISSUER,
        "aud": settings.JWT_AUDIENCE,
        "iat": int(now.timestamp()),
        "exp": int(expire.timestamp()),
    }

    raw_token = jwt.encode(payload, settings.JWT_SECRET, algorithm=settings.JWT_ALGORITHM)
    return raw_token, expire


def decode_token(token: str, expected_type: str = "access") -> dict[str, Any]:
    """
    Decode and validate a JWT token.
    Verifies signature, expiration, issuer, audience, and token_type.

    Raises:
        jwt.ExpiredSignatureError: if expired.
        jwt.InvalidTokenError: if invalid signature, issuer, audience, or token_type mismatch.
    """
    settings = get_settings()
    payload = jwt.decode(
        token,
        settings.JWT_SECRET,
        algorithms=[settings.JWT_ALGORITHM],
        issuer=settings.JWT_ISSUER,
        audience=settings.JWT_AUDIENCE,
        options={"require": ["exp", "iss", "aud", "sub", "token_type"]},
    )

    if payload.get("token_type") != expected_type:
        raise jwt.InvalidTokenError(
            f"Invalid token type: expected '{expected_type}', got '{payload.get('token_type')}'"
        )

    return payload

