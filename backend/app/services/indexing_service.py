"""
SentinelRAG — Vector Indexing Service.

Manages vector embeddings and persistence in ChromaDB 'sentinelrag_chunks' collection.
Applies ONNX all-MiniLM-L6-v2 embeddings and enforces owner-scoped vector operations.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Optional

import chromadb
from chromadb.utils import embedding_functions

from app.core.config import get_settings
from app.core.logging import get_logger
from app.db.chromadb import chromadb_manager

logger = get_logger(__name__)

COLLECTION_NAME = "sentinelrag_chunks"
EMBEDDING_MODEL_VERSION = "all-MiniLM-L6-v2"


class IndexingService:
    """Manages document vector indexing, retrieval filtering, and vector deletion in ChromaDB."""

    def __init__(self, collection_name: str = COLLECTION_NAME):
        self.collection_name = collection_name
        self._embedding_function: Optional[Any] = None

    @property
    def embedding_function(self):
        """Lazily initialize the default ONNX embedding function."""
        if self._embedding_function is None:
            self._embedding_function = embedding_functions.DefaultEmbeddingFunction()
        return self._embedding_function

    def get_collection(self):
        """Get or create the ChromaDB collection with the standard embedding function."""
        client = chromadb_manager.get_client()
        return client.get_or_create_collection(
            name=self.collection_name,
            embedding_function=self.embedding_function,
            metadata={"hnsw:space": "cosine"},
        )

    def index_chunks(self, chunks: list[dict[str, Any]]) -> int:
        """
        Index a batch of document chunks into ChromaDB.

        Args:
            chunks: List of chunk dictionaries containing chunk_id, text,
                    document_id, owner_id, page_number, chunk_index, source_filename.

        Returns:
            int: Number of chunks successfully indexed.
        """
        if not chunks:
            return 0

        collection = self.get_collection()
        now_iso = datetime.now(timezone.utc).isoformat()

        ids: list[str] = []
        documents: list[str] = []
        metadatas: list[dict[str, Any]] = []

        for c in chunks:
            ids.append(c["chunk_id"])
            documents.append(c["text"])
            metadatas.append({
                "owner_id": str(c["owner_id"]),
                "document_id": str(c["document_id"]),
                "page_number": int(c.get("page_number", 1)),
                "chunk_index": int(c.get("chunk_index", 0)),
                "trust_status": "allow",
                "document_status": "indexed",
                "source_filename": str(c.get("source_filename", "unknown.pdf")),
                "embedding_model_version": EMBEDDING_MODEL_VERSION,
                "created_at": now_iso,
            })

        # Upsert ensures idempotent indexing
        collection.upsert(
            ids=ids,
            documents=documents,
            metadatas=metadatas,
        )

        logger.info(
            "Successfully indexed chunks into ChromaDB",
            extra={
                "collection": self.collection_name,
                "count": len(ids),
                "document_id": chunks[0].get("document_id"),
            },
        )
        return len(ids)

    def count_document_vectors(self, document_id: str, owner_id: str) -> int:
        """Count existing vectors for a specific document and owner."""
        collection = self.get_collection()
        where_filter = {
            "$and": [
                {"document_id": {"$eq": document_id}},
                {"owner_id": {"$eq": owner_id}},
            ]
        }
        res = collection.get(where=where_filter)
        return len(res.get("ids", []))

    def delete_document_vectors(self, document_id: str, owner_id: str) -> int:
        """
        Delete all vector records for a specific document ID and owner ID.

        Enforces tenant isolation by always including owner_id in the deletion query.

        Returns:
            int: Number of vectors deleted.
        """
        collection = self.get_collection()
        where_filter = {
            "$and": [
                {"document_id": {"$eq": document_id}},
                {"owner_id": {"$eq": owner_id}},
            ]
        }

        # Check existing count before deletion
        try:
            res = collection.get(where=where_filter)
            count = len(res.get("ids", []))
            if count > 0:
                collection.delete(where=where_filter)
                logger.info(
                    "Deleted vectors from ChromaDB",
                    extra={
                        "document_id": document_id,
                        "owner_id": owner_id,
                        "deleted_count": count,
                    },
                )
            return count
        except Exception as exc:  # noqa: BLE001
            logger.error(
                "Error deleting vectors from ChromaDB",
                extra={
                    "document_id": document_id,
                    "owner_id": owner_id,
                    "error": str(exc),
                },
            )
            # Re-raise so caller knows vector cleanup failed
            raise


indexing_service = IndexingService()

