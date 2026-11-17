"""
SentinelRAG — Authentication Service.

Coordinates user registration, credential verification, JWT issuance,
and revocable refresh token session rotation.
"""
from __future__ import annotations

from typing import Optional, Tuple
import jwt

from app.core.config import get_settings
from app.core.logging import get_logger
from app.core.security import (
    create_access_token,
    create_refresh_token,
    decode_token,
    hash_password,
    hash_token,
    verify_password,
)
from app.db.users_repo import users_repo
from app.models.user import UserInDB
from app.schemas.auth import UserLoginRequest, UserRegisterRequest

logger = get_logger(__name__)


class AuthenticationError(Exception):
    """Base exception for authentication failures."""
    def __init__(self, message: str, code: str = "AUTH_FAILED"):
        super().__init__(message)
        self.message = message
        self.code = code


class AuthService:
    """Core authentication business logic."""

    async def register(self, req: UserRegisterRequest) -> UserInDB:
        """Register a new user with Argon2id password hash."""
        existing = await users_repo.get_by_email(req.email)
        if existing:
            # Generic error to prevent email enumeration or standard duplicate error
            raise AuthenticationError("An account with this email already exists", "EMAIL_EXISTS")

        pwd_hash = hash_password(req.password)
        user = await users_repo.create_user(
            email=req.email,
            password_hash=pwd_hash,
            display_name=req.display_name,
            role="user",
        )
        logger.info("User registered successfully", extra={"user_id": user.id})
        return user

    async def login(
        self,
        req: UserLoginRequest,
        user_agent: Optional[str] = None,
        ip_address: Optional[str] = None,
    ) -> Tuple[str, str, int, UserInDB]:
        """
        Authenticate user credentials and issue token pair.
        Returns (access_token, refresh_token, expires_in_seconds, user).
        """
        user = await users_repo.get_by_email(req.email)
        if not user or not verify_password(req.password, user.password_hash):
            # Generic message to prevent user enumeration
            raise AuthenticationError("Invalid email or password", "INVALID_CREDENTIALS")

        if user.status != "active":
            raise AuthenticationError("User account is inactive or suspended", "ACCOUNT_INACTIVE")

        # Create access token and refresh token
        settings = get_settings()
        access_token = create_access_token(
            user_id=user.id,
            email=user.email,
            role=user.role,
        )
        raw_refresh, refresh_expires_at = create_refresh_token(user_id=user.id)

        # Store hashed refresh token session in MongoDB
        token_h = hash_token(raw_refresh)
        await users_repo.create_refresh_session(
            user_id=user.id,
            token_hash=token_h,
            expires_at=refresh_expires_at,
            user_agent=user_agent,
            ip_address=ip_address,
        )

        # Update last login timestamp
        await users_repo.update_last_login(user.id)
        logger.info("User logged in successfully", extra={"user_id": user.id})

        expires_in = settings.ACCESS_TOKEN_TTL_MINUTES * 60
        return access_token, raw_refresh, expires_in, user

    async def refresh_session(
        self,
        raw_refresh_token: str,
        user_agent: Optional[str] = None,
        ip_address: Optional[str] = None,
    ) -> Tuple[str, str, int, UserInDB]:
        """
        Rotate refresh token and issue a new access token.
        Enforces:
          - JWT signature and expiration validity.
          - Session existence in MongoDB.
          - Session non-revocation.
          - Token rotation (old session revoked, new session created).
        """
        try:
            payload = decode_token(raw_refresh_token, expected_type="refresh")
        except jwt.ExpiredSignatureError:
            raise AuthenticationError("Refresh token has expired", "TOKEN_EXPIRED")
        except jwt.InvalidTokenError as exc:
            raise AuthenticationError(f"Invalid refresh token: {str(exc)}", "TOKEN_INVALID")

        user_id = payload.get("sub")
        if not user_id:
            raise AuthenticationError("Invalid refresh token payload", "TOKEN_INVALID")

        # Verify against stored session
        token_h = hash_token(raw_refresh_token)
        session = await users_repo.get_refresh_session(token_h)
        if not session:
            raise AuthenticationError("Session not found or has expired", "SESSION_NOT_FOUND")

        if session.revoked:
            # If a revoked refresh token is presented, potential token reuse attack!
            # Revoke all sessions for this user to protect the account
            await users_repo.revoke_all_user_sessions(user_id)
            logger.warning(
                "Revoked refresh token presented! Possible token theft. Revoked all sessions.",
                extra={"user_id": user_id},
            )
            raise AuthenticationError("Refresh token has been revoked", "TOKEN_REVOKED")

        user = await users_repo.get_by_id(user_id)
        if not user or user.status != "active":
            raise AuthenticationError("User is no longer active", "ACCOUNT_INACTIVE")

        # Revoke the old refresh session (Token Rotation)
        await users_repo.revoke_refresh_session(token_h)

        # Issue new token pair
        settings = get_settings()
        new_access = create_access_token(
            user_id=user.id,
            email=user.email,
            role=user.role,
        )
        new_refresh, new_expires_at = create_refresh_token(user_id=user.id)
        new_token_h = hash_token(new_refresh)

        # Store new session
        await users_repo.create_refresh_session(
            user_id=user.id,
            token_hash=new_token_h,
            expires_at=new_expires_at,
            user_agent=user_agent,
            ip_address=ip_address,
        )

        logger.info("Session refreshed and rotated successfully", extra={"user_id": user.id})
        expires_in = settings.ACCESS_TOKEN_TTL_MINUTES * 60
        return new_access, new_refresh, expires_in, user

    async def logout(self, raw_refresh_token: Optional[str]) -> bool:
        """Revoke the refresh token session in MongoDB."""
        if not raw_refresh_token:
            return True
        token_h = hash_token(raw_refresh_token)
        return await users_repo.revoke_refresh_session(token_h)


# Module-level singleton
auth_service = AuthService()

