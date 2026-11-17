"""
SentinelRAG — Authentication and Security Dependencies.

Provides reusable FastAPI dependencies to authenticate incoming requests via
JWT Bearer access tokens. Identity is derived strictly on the server-side.
"""
from __future__ import annotations

import jwt
from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from app.core.security import decode_token
from app.db.users_repo import users_repo
from app.models.user import UserInDB
from app.utils.correlation import get_correlation_id

# Auto-extracts "Bearer <token>" from Authorization header
security_bearer = HTTPBearer(auto_error=False)


async def get_current_user(
    request: Request,
    credentials: HTTPAuthorizationCredentials | None = Depends(security_bearer),
) -> UserInDB:
    """
    Authenticate request via JWT Bearer access token.
    Derives user identity exclusively from validated token claims and MongoDB.

    Raises:
        HTTPException(401): if token is missing, invalid, expired, or user not found.
    """
    correlation_id = get_correlation_id(request)

    if not credentials or not credentials.credentials:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={
                "code": "AUTHENTICATION_REQUIRED",
                "message": "Authentication credentials were not provided",
                "correlation_id": correlation_id,
            },
            headers={"WWW-Authenticate": "Bearer"},
        )

    token = credentials.credentials
    try:
        payload = decode_token(token, expected_type="access")
    except jwt.ExpiredSignatureError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={
                "code": "TOKEN_EXPIRED",
                "message": "Access token has expired",
                "correlation_id": correlation_id,
            },
            headers={"WWW-Authenticate": "Bearer"},
        )
    except jwt.InvalidTokenError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={
                "code": "INVALID_TOKEN",
                "message": f"Could not validate credentials: {str(exc)}",
                "correlation_id": correlation_id,
            },
            headers={"WWW-Authenticate": "Bearer"},
        )

    user_id: str | None = payload.get("sub")
    if not user_id:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={
                "code": "INVALID_TOKEN_CLAIMS",
                "message": "Token payload missing user identifier",
                "correlation_id": correlation_id,
            },
            headers={"WWW-Authenticate": "Bearer"},
        )

    user = await users_repo.get_by_id(user_id)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={
                "code": "USER_NOT_FOUND",
                "message": "User associated with this token does not exist",
                "correlation_id": correlation_id,
            },
            headers={"WWW-Authenticate": "Bearer"},
        )

    return user


async def get_current_active_user(
    request: Request,
    current_user: UserInDB = Depends(get_current_user),
) -> UserInDB:
    """Ensure that the authenticated user account is active."""
    if current_user.status != "active":
        correlation_id = get_correlation_id(request)
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={
                "code": "ACCOUNT_INACTIVE",
                "message": "User account has been deactivated or suspended",
                "correlation_id": correlation_id,
            },
        )
    return current_user

