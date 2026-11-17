"""
SentinelRAG — ChromaDB Connection Manager.

Manages the lifecycle of the ChromaDB persistent vector store client.

Security note: ChromaDB metadata filters are NOT a security boundary.
Backend authorization code must enforce owner-scoped queries independently.
This module only manages the connection; retrieval authorization lives in
the RetrievalService (Phase 4+).
"""
from __future__ import annotations

import time
from typing import Any

import chromadb
from chromadb import PersistentClient

from app.core.config import get_settings
from app.core.logging import get_logger

logger = get_logger(__name__)


class ChromaDBManager:
    """
    Manages the ChromaDB persistent client lifecycle.

    Usage:
        chromadb_manager.initialize()         # at startup
        client = chromadb_manager.get_client()  # during request handling
    """

    def __init__(self) -> None:
        self._client: PersistentClient | None = None

    def initialize(self) -> None:
        """
        Create a ChromaDB persistent client.

        The persistence directory is read from application settings.
        ChromaDB will create the directory if it does not exist.
        """
        settings = get_settings()
        persist_dir = settings.CHROMA_PERSIST_DIR
        logger.info("Initializing ChromaDB", extra={"persist_dir": persist_dir})

        self._client = chromadb.PersistentClient(
            path=persist_dir,
            settings=chromadb.config.Settings(anonymized_telemetry=False),
        )
        # Verify by listing existing collections (creates the store if new)
        collections = self._client.list_collections()
        logger.info(
            "ChromaDB initialized",
            extra={
                "persist_dir": persist_dir,
                "existing_collections": len(collections),
            },
        )

    def get_client(self) -> PersistentClient:
        """
        Return the active ChromaDB client.

        Raises RuntimeError if called before initialize().
        """
        if self._client is None:
            raise RuntimeError(
                "ChromaDB is not initialized. Ensure initialize() was called at startup."
            )
        return self._client

    def health_check(self) -> dict[str, Any]:
        """
        Verify ChromaDB is reachable by listing collections.

        Returns:
            {"status": "healthy", "collections": [...], "latency_ms": float}
            or
            {"status": "unhealthy", "error": str}
        """
        if self._client is None:
            return {"status": "unhealthy", "error": "ChromaDB client is not initialized"}

        start = time.monotonic()
        try:
            collections = self._client.list_collections()
            latency_ms = round((time.monotonic() - start) * 1000, 2)
            collection_names = [c.name for c in collections]
            return {
                "status": "healthy",
                "latency_ms": latency_ms,
                "collections": collection_names,
            }
        except Exception as exc:  # noqa: BLE001
            logger.warning("ChromaDB health check failed", extra={"error": str(exc)})
            return {"status": "unhealthy", "error": str(exc)}


# Module-level singleton — imported by route handlers and services
chromadb_manager = ChromaDBManager()

