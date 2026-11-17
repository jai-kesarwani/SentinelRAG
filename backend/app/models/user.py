"""
SentinelRAG — User and Session Data Models.

Matches MongoDB collections defined in docs/05_DATABASE_SPECIFICATION.md:
  - users
  - refresh_tokens
"""
from __future__ import annotations

from datetime import datetime
from typing import Any, Optional

from pydantic import BaseModel, Field


class UserInDB(BaseModel):
    """User representation stored in MongoDB 'users' collection."""

    id: str = Field(alias="_id")
    email: str
    password_hash: str
    display_name: str
    role: str = "user"  # "user" | "admin"
    status: str = "active"  # "active" | "suspended"
    created_at: datetime
    updated_at: datetime
    last_login_at: Optional[datetime] = None

    def to_public_dict(self) -> dict[str, Any]:
        """Convert to safe public dictionary without password_hash."""
        return {
            "id": self.id,
            "_id": self.id,
            "email": self.email,
            "display_name": self.display_name,
            "role": self.role,
            "status": self.status,
            "created_at": self.created_at,
            "last_login_at": self.last_login_at,
        }


class RefreshTokenInDB(BaseModel):
    """Refresh session representation stored in MongoDB 'refresh_tokens' collection."""

    id: str = Field(alias="_id")
    user_id: str
    token_hash: str  # SHA-256 of the raw JWT refresh token
    expires_at: datetime
    created_at: datetime
    revoked: bool = False
    revoked_at: Optional[datetime] = None
    user_agent: Optional[str] = None
    ip_address: Optional[str] = None

