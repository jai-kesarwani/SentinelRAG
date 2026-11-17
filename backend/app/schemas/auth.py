"""
SentinelRAG — Authentication Request and Response Schemas.

Pydantic v2 schemas for user registration, login, token refresh, and profile retrieval.
"""
from __future__ import annotations

import re
from datetime import datetime
from typing import Optional

from pydantic import BaseModel, ConfigDict, EmailStr, Field, field_validator


class UserRegisterRequest(BaseModel):
    """Payload for user registration."""

    model_config = ConfigDict(str_strip_whitespace=True)

    email: EmailStr = Field(description="User email address")
    password: str = Field(min_length=8, max_length=128, description="Password (at least 8 characters)")
    display_name: str = Field(min_length=2, max_length=64, description="User display name")

    @field_validator("email")
    @classmethod
    def normalize_email(cls, v: str) -> str:
        return v.lower().strip()

    @field_validator("password")
    @classmethod
    def validate_password_strength(cls, v: str) -> str:
        if len(v) < 8:
            raise ValueError("Password must be at least 8 characters long")
        # Require at least one letter and one number or special character
        if not re.search(r"[a-zA-Z]", v):
            raise ValueError("Password must contain at least one letter")
        if not re.search(r"[0-9!@#$%^&*(),.?\":{}|<>]", v):
            raise ValueError("Password must contain at least one digit or special character")
        return v


class UserLoginRequest(BaseModel):
    """Payload for user login."""

    model_config = ConfigDict(str_strip_whitespace=True)

    email: EmailStr = Field(description="User email address")
    password: str = Field(min_length=1, max_length=128, description="User password")

    @field_validator("email")
    @classmethod
    def normalize_email(cls, v: str) -> str:
        return v.lower().strip()


class UserResponse(BaseModel):
    """Public user profile response."""

    id: str = Field(alias="_id", default="")
    email: str
    display_name: str
    role: str = "user"
    status: str = "active"
    created_at: datetime
    last_login_at: Optional[datetime] = None

    model_config = ConfigDict(populate_by_name=True)


class TokenResponse(BaseModel):
    """Access token response payload."""

    access_token: str
    token_type: str = "bearer"
    expires_in_seconds: int
    user: UserResponse


class RefreshTokenRequest(BaseModel):
    """Optional payload for clients that pass refresh token in JSON body."""

    refresh_token: Optional[str] = None


class LogoutResponse(BaseModel):
    """Response returned upon successful logout."""

    revoked: bool = True
    message: str = "Logged out successfully"

