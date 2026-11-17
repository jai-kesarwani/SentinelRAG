"""
SentinelRAG — Document Domain Models.

Matches MongoDB 'documents' collection in docs/05_DATABASE_SPECIFICATION.md.
"""
from __future__ import annotations

from datetime import datetime
from typing import Any, Optional

from pydantic import BaseModel, Field


class DocumentTrustInfo(BaseModel):
    """Trust and screening status for an ingested document."""

    status: str = "allow"  # allow | review | quarantined
    risk_level: str = "low"  # low | medium | high
    signals: list[str] = Field(default_factory=list)
    scanner_version: str = "1.0.0"
    classifier_version: Optional[str] = None
    scanned_at: Optional[datetime] = None
    policy_decision: str = "allow"


class DocumentInDB(BaseModel):
    """MongoDB record for an uploaded document."""

    id: str = Field(alias="_id")
    owner_id: str
    original_filename: str
    storage_key: str
    mime_type: str = "application/pdf"
    file_size_bytes: int
    sha256: str
    status: str = "uploaded"  # uploaded, processing, indexed, review, quarantined, failed, deleting, deleted
    page_count: int = 0
    chunk_count: int = 0
    trust: DocumentTrustInfo = Field(default_factory=DocumentTrustInfo)
    error_message: Optional[str] = None
    created_at: datetime
    updated_at: datetime
    deleted_at: Optional[datetime] = None

    def to_public_dict(self) -> dict[str, Any]:
        """Convert to safe public dictionary without internal storage paths."""
        return {
            "id": self.id,
            "_id": self.id,
            "owner_id": self.owner_id,
            "original_filename": self.original_filename,
            "file_size_bytes": self.file_size_bytes,
            "mime_type": self.mime_type,
            "status": self.status,
            "page_count": self.page_count,
            "chunk_count": self.chunk_count,
            "sha256": self.sha256,
            "error_message": self.error_message,
            "trust": self.trust.model_dump(),
            "created_at": self.created_at,
            "updated_at": self.updated_at,
        }

