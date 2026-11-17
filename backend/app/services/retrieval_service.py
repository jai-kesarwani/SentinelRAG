"""
SentinelRAG — Secure Document Retrieval Service.

Queries ChromaDB vector collection and enforces multi-layered server-side authorization:
1. ChromaDB metadata filter by authenticated owner_id.
2. Backend validation of returned chunk owner_id against authenticated identity.
3. Live document status & ownership verification against MongoDB 'documents' collection.
4. Exclusion of deleted, quarantined, or unapproved document chunks.
"""
from __future__ import annotations

from typing import Any, Optional

from pydantic import BaseModel

from app.core.logging import get_logger
from app.db.documents_repo import documents_repo
from app.services.indexing_service import COLLECTION_NAME, indexing_service

logger = get_logger(__name__)


class RetrievedChunk(BaseModel):
    """Structured representation of an authorized, validated document chunk."""

    chunk_id: str
    document_id: str
    owner_id: str
    page_number: int
    chunk_index: int
    source_filename: str
    text: str
    distance: Optional[float] = None
    relevance_score: Optional[float] = None


class RetrievalService:
    """Manages secure semantic search and backend authorization verification for RAG."""

    def __init__(self, top_k_default: int = 5):
        self.top_k_default = top_k_default

    async def retrieve_relevant_chunks(
        self,
        query: str,
        owner_id: str,
        top_k: Optional[int] = None,
        max_distance: float = 1.2,
    ) -> list[RetrievedChunk]:
        """
        Retrieve relevant chunks for a user query with strict authorization checks.

        Args:
            query: User search text or question.
            owner_id: Authenticated user ID (derived from backend session).
            top_k: Maximum number of chunks to return.
            max_distance: Maximum cosine distance threshold to prune irrelevant matches.

        Returns:
            list[RetrievedChunk]: Filtered, verified, authorized chunks.
        """
        cleaned_query = query.strip()
        if not cleaned_query:
            return []

        limit = min(max(top_k or self.top_k_default, 1), 20)
        collection = indexing_service.get_collection()

        # Step 1: ChromaDB query filtered by owner_id
        # Vector search using the same embedding function used in ingestion
        try:
            results = collection.query(
                query_texts=[cleaned_query],
                n_results=limit,
                where={"owner_id": {"$eq": owner_id}},
                include=["documents", "metadatas", "distances"],
            )
        except Exception as exc:  # noqa: BLE001
            logger.error("Vector search query failed in ChromaDB", extra={"error": str(exc), "owner_id": owner_id})
            return []

        # Step 2: Unpack results safely
        ids_list = results.get("ids", [[]])[0]
        docs_list = results.get("documents", [[]])[0]
        metas_list = results.get("metadatas", [[]])[0]
        dists_list = results.get("distances", [[]])[0] if results.get("distances") else []

        if not ids_list:
            logger.info("No chunks matched vector search query", extra={"owner_id": owner_id})
            return []

        # Cache document records for the request to avoid repetitive DB lookups
        verified_doc_cache: dict[str, bool] = {}
        authorized_chunks: list[RetrievedChunk] = []

        for idx, chunk_id in enumerate(ids_list):
            meta = metas_list[idx] if idx < len(metas_list) else {}
            chunk_text = docs_list[idx] if idx < len(docs_list) else ""
            dist = dists_list[idx] if idx < len(dists_list) else None

            # Compute normalized relevance score (1 - cosine distance)
            relevance = max(0.0, 1.0 - dist) if dist is not None else None

            # Distance threshold filtering
            if dist is not None and dist > max_distance:
                continue

            # SECURITY CHECK 1: Verify owner_id matches authenticated session
            chunk_owner = str(meta.get("owner_id", ""))
            if chunk_owner != owner_id:
                logger.error(
                    "SECURITY ALERT: ChromaDB returned chunk belonging to different owner",
                    extra={
                        "chunk_id": chunk_id,
                        "chunk_owner": chunk_owner,
                        "session_owner": owner_id,
                    },
                )
                # Drop chunk immediately!
                continue

            doc_id = str(meta.get("document_id", ""))
            if not doc_id:
                logger.warning("Chunk missing document_id metadata", extra={"chunk_id": chunk_id})
                continue

            # SECURITY CHECK 2: Live document status, trust decision & ownership in MongoDB
            if doc_id not in verified_doc_cache:
                doc_record = await documents_repo.get_by_id(document_id=doc_id, owner_id=owner_id)
                # Ensure document exists, is owned by user, has indexed status, and is explicitly allowed by security policy
                trust_status = getattr(doc_record.trust, "status", "allow") if doc_record else ""
                policy_decision = getattr(doc_record.trust, "policy_decision", "allow") if doc_record else ""
                is_eligible = bool(
                    doc_record
                    and doc_record.owner_id == owner_id
                    and doc_record.status == "indexed"
                    and trust_status == "allow"
                    and policy_decision not in {"quarantined", "review"}
                )
                verified_doc_cache[doc_id] = is_eligible
                if not is_eligible:
                    logger.warning(
                        "Excluded chunk from ineligible, quarantined, or unapproved document",
                        extra={
                            "document_id": doc_id,
                            "status": getattr(doc_record, "status", "not_found"),
                            "trust_status": trust_status,
                        },
                    )

            if not verified_doc_cache[doc_id]:
                continue

            authorized_chunks.append(
                RetrievedChunk(
                    chunk_id=chunk_id,
                    document_id=doc_id,
                    owner_id=owner_id,
                    page_number=int(meta.get("page_number", 1)),
                    chunk_index=int(meta.get("chunk_index", 0)),
                    source_filename=str(meta.get("source_filename", "document.pdf")),
                    text=chunk_text,
                    distance=dist,
                    relevance_score=relevance,
                )
            )

        logger.info(
            "Secure retrieval complete",
            extra={
                "owner_id": owner_id,
                "retrieved_count": len(ids_list),
                "authorized_count": len(authorized_chunks),
            },
        )
        return authorized_chunks


retrieval_service = RetrievalService()

