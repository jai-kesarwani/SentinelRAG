"""
SentinelRAG — Chat & Conversation Domain Models.

Matches MongoDB 'conversations' and 'messages' collections defined in
docs/05_DATABASE_SPECIFICATION.md.
"""
from __future__ import annotations

from datetime import datetime
from typing import Any, Optional

from pydantic import BaseModel, Field


class Citation(BaseModel):
    """Source reference mapping an answer fragment to an authorized document chunk."""

    document_id: str
    chunk_id: str
    page_number: int
    source_filename: str
    excerpt: Optional[str] = None


class MessageInDB(BaseModel):
    """MongoDB record for a message inside a conversation."""

    id: str = Field(alias="_id")
    conversation_id: str
    owner_id: str
    role: str  # "user" | "assistant"
    content: str
    citations: list[Citation] = Field(default_factory=list)
    created_at: datetime
    validation_status: str = "validated"  # "validated" | "unsupported" | "rejected"

    def to_public_dict(self) -> dict[str, Any]:
        """Convert to public dictionary representation."""
        return {
            "id": self.id,
            "conversation_id": self.conversation_id,
            "role": self.role,
            "content": self.content,
            "citations": [c.model_dump() for c in self.citations],
            "created_at": self.created_at,
            "validation_status": self.validation_status,
        }


class ConversationInDB(BaseModel):
    """MongoDB record for a user conversation session."""

    id: str = Field(alias="_id")
    owner_id: str
    title: str = "New Conversation"
    created_at: datetime
    updated_at: datetime

    def to_public_dict(self) -> dict[str, Any]:
        """Convert to public dictionary representation."""
        return {
            "id": self.id,
            "title": self.title,
            "owner_id": self.owner_id,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
        }

