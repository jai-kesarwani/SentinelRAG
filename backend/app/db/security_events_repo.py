"""
SentinelRAG — Security Events Repository.

Handles persistence and audit retrieval for the 'security_events' collection in MongoDB.
"""
from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any, Optional, Tuple

from pymongo import ASCENDING, DESCENDING

from app.core.logging import get_logger
from app.db.mongodb import mongodb_manager
from app.models.security_event import DetectorInfo, SecurityEventInDB

logger = get_logger(__name__)


class SecurityEventsRepository:
    """MongoDB repository for logging and retrieving security events."""

    @property
    def collection(self):
        return mongodb_manager.get_database()["security_events"]

    async def init_indexes(self) -> None:
        """Initialize required MongoDB indexes for security event auditing."""
        try:
            await self.collection.create_index(
                [("owner_id", ASCENDING), ("created_at", DESCENDING)],
                name="idx_security_events_owner_created",
            )
            await self.collection.create_index(
                [("event_type", ASCENDING), ("created_at", DESCENDING)],
                name="idx_security_events_type_created",
            )
            await self.collection.create_index(
                [("correlation_id", ASCENDING)],
                name="idx_security_events_correlation",
            )
            logger.info("MongoDB security_events indexes initialized")
        except Exception as exc:  # noqa: BLE001
            logger.error("Failed to initialize security_events indexes", extra={"error": str(exc)})

    async def record_event(
        self,
        event_type: str,
        severity: str = "low",
        decision: str = "allow",
        reason_code: str = "NORMAL",
        resource_type: str = "document",
        resource_id: Optional[str] = None,
        owner_id: Optional[str] = None,
        actor_user_id: Optional[str] = None,
        correlation_id: Optional[str] = None,
        detector_name: str = "sentinel_deterministic_scanner",
        detector_version: str = "1.0.0",
        safe_metadata: Optional[dict[str, Any]] = None,
    ) -> SecurityEventInDB:
        """
        Record a security event into MongoDB.
        Ensures secrets and full document payloads are never logged.
        """
        now = datetime.now(timezone.utc)
        event_id = str(uuid.uuid4())
        doc = {
            "_id": event_id,
            "owner_id": owner_id,
            "actor_user_id": actor_user_id,
            "correlation_id": correlation_id,
            "event_type": event_type,
            "severity": severity,
            "resource_type": resource_type,
            "resource_id": resource_id,
            "decision": decision,
            "reason_code": reason_code,
            "detector": {
                "name": detector_name,
                "version": detector_version,
            },
            "safe_metadata": safe_metadata or {},
            "created_at": now,
        }
        await self.collection.insert_one(doc)
        logger.info(
            "Security event recorded",
            extra={
                "event_id": event_id,
                "event_type": event_type,
                "severity": severity,
                "decision": decision,
                "resource_id": resource_id,
            },
        )
        return SecurityEventInDB(**doc)

    async def list_by_owner(
        self,
        owner_id: str,
        limit: int = 50,
        skip: int = 0,
    ) -> Tuple[list[SecurityEventInDB], int]:
        """Fetch paginated security events for an owner."""
        query = {"owner_id": owner_id}
        total = await self.collection.count_documents(query)
        cursor = self.collection.find(query).sort("created_at", DESCENDING).skip(skip).limit(limit)

        events: list[SecurityEventInDB] = []
        async for doc in cursor:
            events.append(SecurityEventInDB(**doc))
        return events, total

    async def list_by_resource(
        self,
        resource_id: str,
        owner_id: str,
    ) -> list[SecurityEventInDB]:
        """Fetch audit events for a specific resource, scoped by owner."""
        query = {"resource_id": resource_id, "owner_id": owner_id}
        cursor = self.collection.find(query).sort("created_at", DESCENDING)

        events: list[SecurityEventInDB] = []
        async for doc in cursor:
            events.append(SecurityEventInDB(**doc))
        return events


security_events_repo = SecurityEventsRepository()

