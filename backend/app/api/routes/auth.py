"""
SentinelRAG — Authentication API Endpoints.

Endpoints:
  POST /api/v1/auth/register — Create a new user account
  POST /api/v1/auth/login    — Authenticate credentials, issue access token & refresh cookie
  POST /api/v1/auth/refresh  — Rotate refresh token, issue new access token
  POST /api/v1/auth/logout   — Invalidate refresh token session and clear cookie
  GET  /api/v1/auth/me       — Retrieve current authenticated user profile
"""
from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, Cookie, Depends, HTTPException, Request, Response, status
from fastapi.responses import JSONResponse

from app.api.dependencies import get_current_active_user
from app.core.config import get_settings
from app.models.user import UserInDB
from app.schemas.auth import (
    LogoutResponse,
    RefreshTokenRequest,
    TokenResponse,
    UserLoginRequest,
    UserRegisterRequest,
    UserResponse,
)
from app.services.auth_service import AuthenticationError, auth_service
from app.utils.correlation import get_correlation_id

router = APIRouter(prefix="/auth", tags=["Authentication"])


def _envelope(data: dict | list, correlation_id: str) -> dict:
    """Format success response according to standard API envelope."""
    return {"data": data, "meta": {"correlation_id": correlation_id}}


def _set_refresh_cookie(response: Response, raw_refresh_token: str) -> None:
    """Attach secure HttpOnly refresh token cookie."""
    settings = get_settings()
    max_age_seconds = settings.REFRESH_TOKEN_TTL_DAYS * 24 * 60 * 60
    response.set_cookie(
        key=settings.REFRESH_COOKIE_NAME,
        value=raw_refresh_token,
        max_age=max_age_seconds,
        expires=max_age_seconds,
        httponly=True,
        secure=settings.REFRESH_COOKIE_SECURE,
        samesite=settings.REFRESH_COOKIE_SAMESITE,
        path="/api/v1/auth",  # Scoped strictly to auth endpoints
    )


def _clear_refresh_cookie(response: Response) -> None:
    """Clear refresh token cookie."""
    settings = get_settings()
    response.delete_cookie(
        key=settings.REFRESH_COOKIE_NAME,
        path="/api/v1/auth",
        httponly=True,
        secure=settings.REFRESH_COOKIE_SECURE,
        samesite=settings.REFRESH_COOKIE_SAMESITE,
    )


@router.post(
    "/register",
    status_code=status.HTTP_201_CREATED,
    summary="Register a new user account",
)
async def register(request: Request, body: UserRegisterRequest) -> dict:
    """Register a new user account with secure Argon2id password hash."""
    correlation_id = get_correlation_id(request)
    try:
        user = await auth_service.register(body)
        user_response = UserResponse(**user.to_public_dict())
        return _envelope(user_response.model_dump(), correlation_id)
    except AuthenticationError as exc:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT if exc.code == "EMAIL_EXISTS" else status.HTTP_400_BAD_REQUEST,
            detail={
                "code": exc.code,
                "message": exc.message,
                "correlation_id": correlation_id,
            },
        )


@router.post(
    "/login",
    summary="User login with email and password",
)
async def login(
    request: Request,
    response: Response,
    body: UserLoginRequest,
) -> dict:
    """
    Authenticate user credentials.
    Returns short-lived JWT access token in response body and sets
    a secure HttpOnly refresh token cookie.
    """
    correlation_id = get_correlation_id(request)
    user_agent = request.headers.get("User-Agent")
    ip_address = request.client.host if request.client else None

    try:
        access_token, refresh_token, expires_in, user = await auth_service.login(
            req=body,
            user_agent=user_agent,
            ip_address=ip_address,
        )

        _set_refresh_cookie(response, refresh_token)

        token_response = TokenResponse(
            access_token=access_token,
            token_type="bearer",
            expires_in_seconds=expires_in,
            user=UserResponse(**user.to_public_dict()),
        )
        return _envelope(token_response.model_dump(), correlation_id)
    except AuthenticationError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={
                "code": exc.code,
                "message": exc.message,
                "correlation_id": correlation_id,
            },
        )


@router.post(
    "/refresh",
    summary="Refresh access token and rotate refresh session",
)
async def refresh_session(
    request: Request,
    response: Response,
    body: Optional[RefreshTokenRequest] = None,
    sentinel_refresh: Optional[str] = Cookie(default=None),
) -> dict:
    """
    Exchange valid refresh token for a new access token and rotated refresh token.
    Token can be supplied via HttpOnly cookie or optional JSON body.
    """
    correlation_id = get_correlation_id(request)
    # Check cookie first, then body fallback
    raw_token = sentinel_refresh or (body.refresh_token if body else None)

    if not raw_token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={
                "code": "REFRESH_TOKEN_REQUIRED",
                "message": "Refresh token not provided in cookie or body",
                "correlation_id": correlation_id,
            },
        )

    user_agent = request.headers.get("User-Agent")
    ip_address = request.client.host if request.client else None

    try:
        new_access, new_refresh, expires_in, user = await auth_service.refresh_session(
            raw_refresh_token=raw_token,
            user_agent=user_agent,
            ip_address=ip_address,
        )

        _set_refresh_cookie(response, new_refresh)

        token_response = TokenResponse(
            access_token=new_access,
            token_type="bearer",
            expires_in_seconds=expires_in,
            user=UserResponse(**user.to_public_dict()),
        )
        return _envelope(token_response.model_dump(), correlation_id)
    except AuthenticationError as exc:
        # Clear invalid cookie on failure
        _clear_refresh_cookie(response)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={
                "code": exc.code,
                "message": exc.message,
                "correlation_id": correlation_id,
            },
        )


@router.post(
    "/logout",
    summary="Logout user and invalidate session",
)
async def logout(
    request: Request,
    response: Response,
    body: Optional[RefreshTokenRequest] = None,
    sentinel_refresh: Optional[str] = Cookie(default=None),
) -> dict:
    """Invalidate current refresh session and clear authentication cookies."""
    correlation_id = get_correlation_id(request)
    raw_token = sentinel_refresh or (body.refresh_token if body else None)

    if raw_token:
        await auth_service.logout(raw_token)

    _clear_refresh_cookie(response)
    logout_response = LogoutResponse(revoked=True, message="Logged out successfully")
    return _envelope(logout_response.model_dump(), correlation_id)


@router.get(
    "/me",
    summary="Get current authenticated user profile",
)
async def get_me(
    request: Request,
    current_user: UserInDB = Depends(get_current_active_user),
) -> dict:
    """Retrieve verified profile of currently logged-in user."""
    correlation_id = get_correlation_id(request)
    user_response = UserResponse(**current_user.to_public_dict())
    return _envelope(user_response.model_dump(), correlation_id)

