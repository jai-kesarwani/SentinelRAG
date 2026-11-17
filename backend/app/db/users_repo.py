"""
SentinelRAG — Users and Refresh Tokens Repository.

Performs all database operations for user accounts and refresh sessions.
Reuses the centralized MongoDBManager singleton.
"""
from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Optional

from pymongo import ASCENDING
from pymongo.errors import DuplicateKeyError

from app.db.mongodb import mongodb_manager
from app.models.user import UserInDB, RefreshTokenInDB
from app.core.logging import get_logger

logger = get_logger(__name__)


class UsersRepository:
    """Repository handling persistence for users and refresh token sessions."""

    @property
    def users_col(self):
        return mongodb_manager.get_database()["users"]

    @property
    def refresh_tokens_col(self):
        return mongodb_manager.get_database()["refresh_tokens"]

    async def init_indexes(self) -> None:
        """Create necessary indexes for performance and unique constraints."""
        try:
            # Users indexes: unique normalized email, and status index
            await self.users_col.create_index(
                [("email", ASCENDING)],
                unique=True,
                name="idx_users_email_unique",
            )
            await self.users_col.create_index(
                [("status", ASCENDING)],
                name="idx_users_status",
            )

            # Refresh tokens indexes: token_hash lookup, user_id lookup, and TTL index on expires_at
            await self.refresh_tokens_col.create_index(
                [("token_hash", ASCENDING)],
                unique=True,
                name="idx_refresh_tokens_hash",
            )
            await self.refresh_tokens_col.create_index(
                [("user_id", ASCENDING)],
                name="idx_refresh_tokens_user_id",
            )
            # Automatic MongoDB TTL expiration index
            await self.refresh_tokens_col.create_index(
                [("expires_at", ASCENDING)],
                expireAfterSeconds=0,
                name="idx_refresh_tokens_ttl",
            )
            logger.info("MongoDB users & refresh_tokens indexes initialized")
        except Exception as exc:  # noqa: BLE001
            logger.error("Failed to initialize MongoDB auth indexes", extra={"error": str(exc)})

    async def create_user(
        self,
        email: str,
        password_hash: str,
        display_name: str,
        role: str = "user",
    ) -> UserInDB:
        """
        Create a new user in MongoDB.
        Raises ValueError if email is already registered.
        """
        now = datetime.now(timezone.utc)
        user_id = str(uuid.uuid4())
        doc = {
            "_id": user_id,
            "email": email.lower().strip(),
            "password_hash": password_hash,
            "display_name": display_name.strip(),
            "role": role,
            "status": "active",
            "created_at": now,
            "updated_at": now,
            "last_login_at": None,
        }

        try:
            await self.users_col.insert_one(doc)
            return UserInDB(**doc)
        except DuplicateKeyError:
            raise ValueError("An account with this email already exists")

    async def get_by_email(self, email: str) -> Optional[UserInDB]:
        """Fetch a user by normalized email."""
        doc = await self.users_col.find_one({"email": email.lower().strip()})
        if not doc:
            return None
        return UserInDB(**doc)

    async def get_by_id(self, user_id: str) -> Optional[UserInDB]:
        """Fetch a user by ID."""
        doc = await self.users_col.find_one({"_id": user_id})
        if not doc:
            return None
        return UserInDB(**doc)

    async def update_last_login(self, user_id: str) -> None:
        """Record the timestamp of a successful login."""
        now = datetime.now(timezone.utc)
        await self.users_col.update_one(
            {"_id": user_id},
            {"$set": {"last_login_at": now, "updated_at": now}},
        )

    # ------------------------------------------------------------------ #
    # Refresh Session Methods
    # ------------------------------------------------------------------ #

    async def create_refresh_session(
        self,
        user_id: str,
        token_hash: str,
        expires_at: datetime,
        user_agent: Optional[str] = None,
        ip_address: Optional[str] = None,
    ) -> RefreshTokenInDB:
        """Persist a new refresh token session with hashed token."""
        session_id = str(uuid.uuid4())
        now = datetime.now(timezone.utc)
        doc = {
            "_id": session_id,
            "user_id": user_id,
            "token_hash": token_hash,
            "expires_at": expires_at,
            "created_at": now,
            "revoked": False,
            "revoked_at": None,
            "user_agent": user_agent,
            "ip_address": ip_address,
        }
        await self.refresh_tokens_col.insert_one(doc)
        return RefreshTokenInDB(**doc)

    async def get_refresh_session(self, token_hash: str) -> Optional[RefreshTokenInDB]:
        """Find a refresh session by its SHA-256 token hash."""
        doc = await self.refresh_tokens_col.find_one({"token_hash": token_hash})
        if not doc:
            return None
        return RefreshTokenInDB(**doc)

    async def revoke_refresh_session(self, token_hash: str) -> bool:
        """Mark a specific refresh token session as revoked."""
        now = datetime.now(timezone.utc)
        result = await self.refresh_tokens_col.update_one(
            {"token_hash": token_hash, "revoked": False},
            {"$set": {"revoked": True, "revoked_at": now}},
        )
        return result.modified_count > 0

    async def revoke_all_user_sessions(self, user_id: str) -> int:
        """Revoke all active refresh sessions for a user (e.g. on password reset or account freeze)."""
        now = datetime.now(timezone.utc)
        result = await self.refresh_tokens_col.update_many(
            {"user_id": user_id, "revoked": False},
            {"$set": {"revoked": True, "revoked_at": now}},
        )
        return result.modified_count


# Module-level singleton repository
users_repo = UsersRepository()

