"""
SentinelRAG — MongoDB Connection Manager.

Uses Motor (async MongoDB driver). The manager is a singleton initialized at
application startup and torn down at shutdown.

Security note: The connection URI is read from environment configuration only.
Credentials are never hardcoded or logged.
"""
from __future__ import annotations

import time
from typing import Any

from motor.motor_asyncio import AsyncIOMotorClient, AsyncIOMotorDatabase
from pymongo.errors import ConnectionFailure, ServerSelectionTimeoutError

from app.core.config import get_settings
from app.core.logging import get_logger

logger = get_logger(__name__)


class MongoDBManager:
    """
    Manages the application's MongoDB connection lifecycle.

    Usage:
        await mongodb_manager.connect()       # at startup
        db = mongodb_manager.get_database()   # during request handling
        await mongodb_manager.disconnect()    # at shutdown
    """

    def __init__(self) -> None:
        self._client: AsyncIOMotorClient | None = None  # type: ignore[type-arg]
        self._database: AsyncIOMotorDatabase | None = None  # type: ignore[type-arg]

    async def connect(self) -> None:
        """
        Establish connection to MongoDB and verify reachability via ping.

        Raises ConnectionFailure if the server is unreachable.
        """
        settings = get_settings()
        logger.info("Connecting to MongoDB", extra={"database": settings.MONGODB_DATABASE})

        self._client = AsyncIOMotorClient(
            settings.MONGODB_URI,
            serverSelectionTimeoutMS=5_000,  # 5 s timeout for initial connection
            connectTimeoutMS=5_000,
            socketTimeoutMS=10_000,
        )
        self._database = self._client[settings.MONGODB_DATABASE]

        # Verify the connection is live
        await self._client.admin.command("ping")
        logger.info("MongoDB connection established", extra={"database": settings.MONGODB_DATABASE})

    async def disconnect(self) -> None:
        """Close the MongoDB connection gracefully."""
        if self._client is not None:
            self._client.close()
            self._client = None
            self._database = None
            logger.info("MongoDB connection closed")

    def get_database(self) -> AsyncIOMotorDatabase:  # type: ignore[type-arg]
        """
        Return the active database handle.

        Raises RuntimeError if called before connect().
        """
        if self._database is None:
            raise RuntimeError(
                "MongoDB is not connected. Ensure connect() was called at startup."
            )
        return self._database

    async def health_check(self) -> dict[str, Any]:
        """
        Ping MongoDB and return a health status dictionary.

        Returns:
            {"status": "healthy", "latency_ms": float}
            or
            {"status": "unhealthy", "error": str}
        """
        if self._client is None:
            return {"status": "unhealthy", "error": "MongoDB client is not initialized"}

        start = time.monotonic()
        try:
            await self._client.admin.command("ping")
            latency_ms = round((time.monotonic() - start) * 1000, 2)
            return {"status": "healthy", "latency_ms": latency_ms}
        except (ConnectionFailure, ServerSelectionTimeoutError) as exc:
            logger.warning("MongoDB health check failed", extra={"error": str(exc)})
            return {"status": "unhealthy", "error": str(exc)}
        except Exception as exc:  # noqa: BLE001
            logger.error("MongoDB health check unexpected error", extra={"error": str(exc)})
            return {"status": "unhealthy", "error": "Unexpected error during health check"}


# Module-level singleton — imported by route handlers and services
mongodb_manager = MongoDBManager()

