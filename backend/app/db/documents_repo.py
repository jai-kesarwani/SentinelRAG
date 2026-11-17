"""
SentinelRAG — Documents Repository.

Handles persistence for uploaded document metadata in MongoDB 'documents' collection.
Enforces owner-scoped queries on all retrieval, modification, and deletion.
"""
from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any, Optional, Tuple

from pymongo import ASCENDING, DESCENDING

from app.db.mongodb import mongodb_manager
from app.models.document import DocumentInDB, DocumentTrustInfo
from app.core.logging import get_logger

logger = get_logger(__name__)


class DocumentsRepository:
    """MongoDB repository for document metadata."""

    @property
    def collection(self):
        return mongodb_manager.get_database()["documents"]

    async def init_indexes(self) -> None:
        """Create required indexes for fast owner lookups and deduplication."""
        try:
            await self.collection.create_index(
                [("owner_id", ASCENDING), ("created_at", DESCENDING)],
                name="idx_docs_owner_created",
            )
            await self.collection.create_index(
                [("owner_id", ASCENDING), ("status", ASCENDING)],
                name="idx_docs_owner_status",
            )
            await self.collection.create_index(
                [("sha256", ASCENDING), ("owner_id", ASCENDING)],
                name="idx_docs_sha256_owner",
            )
            logger.info("MongoDB documents indexes initialized")
        except Exception as exc:  # noqa: BLE001
            logger.error("Failed to initialize documents indexes", extra={"error": str(exc)})

    async def create_document(
        self,
        owner_id: str,
        original_filename: str,
        storage_key: str,
        file_size_bytes: int,
        sha256: str,
        status: str = "uploaded",
    ) -> DocumentInDB:
        """Create a new document record in MongoDB."""
        now = datetime.now(timezone.utc)
        doc_id = str(uuid.uuid4())
        doc = {
            "_id": doc_id,
            "owner_id": owner_id,
            "original_filename": original_filename,
            "storage_key": storage_key,
            "mime_type": "application/pdf",
            "file_size_bytes": file_size_bytes,
            "sha256": sha256,
            "status": status,
            "page_count": 0,
            "chunk_count": 0,
            "trust": DocumentTrustInfo().model_dump(),
            "error_message": None,
            "created_at": now,
            "updated_at": now,
            "deleted_at": None,
        }
        await self.collection.insert_one(doc)
        return DocumentInDB(**doc)

    async def get_by_id(self, document_id: str, owner_id: str) -> Optional[DocumentInDB]:
        """
        Fetch document metadata by ID and owner.
        Enforces tenant isolation by always filtering by owner_id.
        """
        doc = await self.collection.find_one({
            "_id": document_id,
            "owner_id": owner_id,
            "status": {"$ne": "deleted"},
        })
        if not doc:
            return None
        return DocumentInDB(**doc)

    async def list_by_owner(
        self,
        owner_id: str,
        limit: int = 50,
        skip: int = 0,
    ) -> Tuple[list[DocumentInDB], int]:
        """List documents owned by the specified user, excluding deleted ones."""
        query = {"owner_id": owner_id, "status": {"$ne": "deleted"}}
        total = await self.collection.count_documents(query)
        cursor = self.collection.find(query).sort("created_at", DESCENDING).skip(skip).limit(limit)

        docs = []
        async for item in cursor:
            docs.append(DocumentInDB(**item))
        return docs, total

    async def update_status(
        self,
        document_id: str,
        owner_id: str,
        status: str,
        page_count: Optional[int] = None,
        chunk_count: Optional[int] = None,
        error_message: Optional[str] = None,
        trust: Optional[dict[str, Any]] = None,
    ) -> None:
        """Update processing status, trust findings, and derived metrics."""
        now = datetime.now(timezone.utc)
        update_fields: dict[str, Any] = {"status": status, "updated_at": now}
        if page_count is not None:
            update_fields["page_count"] = page_count
        if chunk_count is not None:
            update_fields["chunk_count"] = chunk_count
        if error_message is not None:
            update_fields["error_message"] = error_message
        if trust is not None:
            update_fields["trust"] = trust

        await self.collection.update_one(
            {"_id": document_id, "owner_id": owner_id},
            {"$set": update_fields},
        )

    async def update_security_scan(
        self,
        document_id: str,
        owner_id: str,
        trust_data: dict[str, Any],
        raw_signals: list[dict[str, Any]],
        new_status: str,
        page_count: int,
    ) -> None:
        """Persist security scan results and raw detection signals on the document."""
        now = datetime.now(timezone.utc)
        await self.collection.update_one(
            {"_id": document_id, "owner_id": owner_id},
            {
                "$set": {
                    "trust": trust_data,
                    "security_signals": raw_signals,
                    "status": new_status,
                    "page_count": page_count,
                    "updated_at": now,
                }
            },
        )

    async def get_security_details(
        self,
        document_id: str,
        owner_id: str,
    ) -> Optional[dict[str, Any]]:
        """Retrieve security scan findings and signals for a document."""
        doc = await self.collection.find_one(
            {"_id": document_id, "owner_id": owner_id, "status": {"$ne": "deleted"}},
            {"storage_key": 0},  # omit storage key
        )
        return doc

    async def list_review_queue(
        self,
        owner_id: str,
        limit: int = 50,
        skip: int = 0,
    ) -> Tuple[list[DocumentInDB], int]:
        """Fetch documents currently in 'review' status awaiting decision."""
        query = {"owner_id": owner_id, "status": "review"}
        total = await self.collection.count_documents(query)
        cursor = self.collection.find(query).sort("created_at", DESCENDING).skip(skip).limit(limit)

        docs: list[DocumentInDB] = []
        async for item in cursor:
            docs.append(DocumentInDB(**item))
        return docs, total

    async def mark_deleting(self, document_id: str, owner_id: str) -> bool:
        """Mark document as 'deleting' to immediately exclude it from retrieval."""
        now = datetime.now(timezone.utc)
        res = await self.collection.update_one(
            {"_id": document_id, "owner_id": owner_id, "status": {"$ne": "deleted"}},
            {"$set": {"status": "deleting", "updated_at": now}},
        )
        return res.modified_count > 0

    async def mark_deleted(self, document_id: str, owner_id: str) -> bool:
        """Mark document as deleted."""
        now = datetime.now(timezone.utc)
        res = await self.collection.update_one(
            {"_id": document_id, "owner_id": owner_id},
            {"$set": {"status": "deleted", "deleted_at": now, "updated_at": now}},
        )
        return res.modified_count > 0


documents_repo = DocumentsRepository()

