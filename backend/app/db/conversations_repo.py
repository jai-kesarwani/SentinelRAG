"""
SentinelRAG — Conversations & Messages Repository.

Handles persistence for conversations and chat messages in MongoDB.
Strictly scopes all queries and deletions to the authenticated owner.
"""
from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any, Optional, Tuple

from pymongo import ASCENDING, DESCENDING

from app.core.logging import get_logger
from app.db.mongodb import mongodb_manager
from app.models.conversation import Citation, ConversationInDB, MessageInDB

logger = get_logger(__name__)


class ConversationsRepository:
    """Repository for managing conversations and message persistence in MongoDB."""

    @property
    def conversations(self):
        return mongodb_manager.get_database()["conversations"]

    @property
    def messages(self):
        return mongodb_manager.get_database()["messages"]

    async def init_indexes(self) -> None:
        """Initialize MongoDB indexes for conversations and messages."""
        try:
            # Conversations index
            await self.conversations.create_index(
                [("owner_id", ASCENDING), ("updated_at", DESCENDING)],
                name="idx_conversations_owner_updated",
            )
            # Messages index
            await self.messages.create_index(
                [("owner_id", ASCENDING), ("conversation_id", ASCENDING), ("created_at", ASCENDING)],
                name="idx_messages_owner_conv_created",
            )
            logger.info("MongoDB conversations & messages indexes initialized")
        except Exception as exc:  # noqa: BLE001
            logger.error("Failed to initialize conversations indexes", extra={"error": str(exc)})

    async def create_conversation(
        self,
        owner_id: str,
        title: Optional[str] = None,
    ) -> ConversationInDB:
        """Create a new conversation belonging to owner_id."""
        now = datetime.now(timezone.utc)
        conv_id = str(uuid.uuid4())
        doc = {
            "_id": conv_id,
            "owner_id": owner_id,
            "title": (title or "New Conversation").strip(),
            "created_at": now,
            "updated_at": now,
        }
        await self.conversations.insert_one(doc)
        return ConversationInDB(**doc)

    async def get_conversation(
        self,
        conversation_id: str,
        owner_id: str,
    ) -> Optional[ConversationInDB]:
        """Fetch conversation by ID, enforcing tenant isolation."""
        doc = await self.conversations.find_one({"_id": conversation_id, "owner_id": owner_id})
        if not doc:
            return None
        return ConversationInDB(**doc)

    async def list_conversations(
        self,
        owner_id: str,
        limit: int = 50,
        skip: int = 0,
    ) -> Tuple[list[ConversationInDB], int]:
        """List all conversations owned by a user, sorted by most recently active."""
        query = {"owner_id": owner_id}
        total = await self.conversations.count_documents(query)
        cursor = self.conversations.find(query).sort("updated_at", DESCENDING).skip(skip).limit(limit)

        results: list[ConversationInDB] = []
        async for doc in cursor:
            results.append(ConversationInDB(**doc))
        return results, total

    async def update_title(
        self,
        conversation_id: str,
        owner_id: str,
        title: str,
    ) -> None:
        """Update the conversation title and touch updated_at."""
        now = datetime.now(timezone.utc)
        await self.conversations.update_one(
            {"_id": conversation_id, "owner_id": owner_id},
            {"$set": {"title": title.strip(), "updated_at": now}},
        )

    async def touch_conversation(self, conversation_id: str, owner_id: str) -> None:
        """Update conversation updated_at timestamp when a new message is posted."""
        now = datetime.now(timezone.utc)
        await self.conversations.update_one(
            {"_id": conversation_id, "owner_id": owner_id},
            {"$set": {"updated_at": now}},
        )

    async def delete_conversation(self, conversation_id: str, owner_id: str) -> bool:
        """Delete conversation and all its messages, scoped strictly to owner."""
        res = await self.conversations.delete_one({"_id": conversation_id, "owner_id": owner_id})
        if res.deleted_count > 0:
            await self.messages.delete_many({"conversation_id": conversation_id, "owner_id": owner_id})
            logger.info(
                "Deleted conversation and messages",
                extra={"conversation_id": conversation_id, "owner_id": owner_id},
            )
            return True
        return False

    async def create_message(
        self,
        conversation_id: str,
        owner_id: str,
        role: str,
        content: str,
        citations: Optional[list[Citation]] = None,
        validation_status: str = "validated",
    ) -> MessageInDB:
        """Persist a message in the conversation."""
        now = datetime.now(timezone.utc)
        msg_id = str(uuid.uuid4())
        citation_dicts = [c.model_dump() for c in (citations or [])]
        doc = {
            "_id": msg_id,
            "conversation_id": conversation_id,
            "owner_id": owner_id,
            "role": role,
            "content": content,
            "citations": citation_dicts,
            "created_at": now,
            "validation_status": validation_status,
        }
        await self.messages.insert_one(doc)
        # Update conversation updated_at
        await self.touch_conversation(conversation_id, owner_id)
        return MessageInDB(**doc)

    async def list_messages(
        self,
        conversation_id: str,
        owner_id: str,
    ) -> list[MessageInDB]:
        """Fetch all messages in a conversation, ordered chronologically."""
        query = {"conversation_id": conversation_id, "owner_id": owner_id}
        cursor = self.messages.find(query).sort("created_at", ASCENDING)
        results: list[MessageInDB] = []
        async for doc in cursor:
            results.append(MessageInDB(**doc))
        return results


conversations_repo = ConversationsRepository()

