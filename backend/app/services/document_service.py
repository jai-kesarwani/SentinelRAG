"""
SentinelRAG — Document Service & Ingestion Coordinator.

Orchestrates the complete document ingestion pipeline with Phase 5 Security Screening:
1. File validation & storage (anti-path-traversal, magic bytes check, SHA-256)
2. Metadata record creation in MongoDB (status: processing)
3. Text extraction by page (PyMuPDF)
4. Document security scanning & prompt injection detection
5. Security decision enforcement:
   - allow: chunking and ChromaDB vector indexing (status: indexed)
   - review: hold for review, vector indexing blocked (status: review)
   - quarantined: vector indexing blocked (status: quarantined)
6. Security event audit recording
7. Rescan and manual review operations
8. Atomic deletion workflow (MongoDB -> ChromaDB -> Disk -> Audit)
"""
from __future__ import annotations

from typing import Any, Optional, Tuple

from fastapi import UploadFile

from app.core.logging import get_logger
from app.db.documents_repo import documents_repo
from app.db.security_events_repo import security_events_repo
from app.models.document import DocumentInDB, DocumentTrustInfo
from app.services.chunking_service import chunking_service
from app.services.indexing_service import indexing_service
from app.services.pdf_service import PDFExtractionError, pdf_service
from app.services.security_scanner import ScanResult, security_scanner
from app.services.storage_service import FileStorageService, StorageValidationError, storage_service

logger = get_logger(__name__)


class DocumentNotFoundError(Exception):
    """Raised when a document is not found or not owned by the requester."""
    pass


class DocumentAccessDeniedError(Exception):
    """Raised when a user lacks authorization to review or modify a document."""
    pass


class DocumentIngestionError(Exception):
    """Raised when an error occurs during PDF parsing, chunking, or indexing."""
    def __init__(self, message: str, doc_id: Optional[str] = None):
        super().__init__(message)
        self.message = message
        self.doc_id = doc_id


class DocumentService:
    """Coordinates document storage, extraction, security scanning, chunking, and lifecycle."""

    def __init__(self, storage: Optional[FileStorageService] = None):
        self.storage = storage or storage_service

    async def ingest_document(
        self,
        owner_id: str,
        upload_file: UploadFile,
        correlation_id: Optional[str] = None,
    ) -> DocumentInDB:
        """
        Coordinate complete ingestion workflow with document security inspection.

        Args:
            owner_id: Authenticated user ID.
            upload_file: FastAPI UploadFile object.
            correlation_id: Request correlation ID for audit logging.

        Returns:
            DocumentInDB: Updated document record with final status (indexed, review, or quarantined).

        Raises:
            StorageValidationError: On invalid file type, size, or magic bytes.
            DocumentIngestionError: On extraction failure.
        """
        # Step 1: Validate and stream file to disk storage
        original_filename = upload_file.filename or "document.pdf"
        try:
            storage_key, file_size_bytes, sha256 = await self.storage.save_upload_file(upload_file)
        except StorageValidationError:
            raise
        except Exception as exc:
            logger.error("File upload storage failure", extra={"error": str(exc), "owner_id": owner_id})
            raise StorageValidationError(f"File upload failed: {exc}") from exc

        # Step 2: Create document record with 'processing' status
        doc = await documents_repo.create_document(
            owner_id=owner_id,
            original_filename=original_filename,
            storage_key=storage_key,
            file_size_bytes=file_size_bytes,
            sha256=sha256,
            status="processing",
        )

        # Step 3: Run extraction and security scanning
        try:
            file_path = self.storage.get_file_path(storage_key)

            # Extract text per page
            pages = pdf_service.extract_text_by_page(file_path)

            # Step 4: Execute Document Security & Prompt Injection Inspection
            scan_result: ScanResult = security_scanner.scan_document(
                document_id=doc.id,
                owner_id=owner_id,
                filename=original_filename,
                pages=pages,
            )

            trust_data = {
                "status": scan_result.policy_decision,
                "risk_level": scan_result.risk_level,
                "signals": [s.pattern_name for s in scan_result.signals],
                "scanner_version": scan_result.scanner_version,
                "classifier_version": scan_result.classifier_version,
                "scanned_at": scan_result.scanned_at,
                "policy_decision": scan_result.policy_decision,
            }
            raw_signals = [s.model_dump() for s in scan_result.signals]

            # Step 5: Audit Log Security Event
            event_type = (
                "document_injection_detected"
                if scan_result.policy_decision == "quarantined"
                else "document_scan_completed"
            )
            await security_events_repo.record_event(
                event_type=event_type,
                severity=scan_result.risk_level,
                decision=scan_result.policy_decision,
                reason_code=scan_result.reason_code,
                resource_type="document",
                resource_id=doc.id,
                owner_id=owner_id,
                actor_user_id=owner_id,
                correlation_id=correlation_id,
                detector_name="sentinel_deterministic_scanner",
                detector_version=scan_result.scanner_version,
                safe_metadata={
                    "signals_count": scan_result.signals_count,
                    "pages_scanned": len(pages),
                    "summary": scan_result.summary,
                },
            )

            # Step 6: Enforce Security Policy Decision
            if scan_result.policy_decision == "allow":
                # Approved -> Proceed to chunking and vector indexing
                chunks = chunking_service.chunk_document_pages(
                    document_id=doc.id,
                    owner_id=owner_id,
                    source_filename=original_filename,
                    pages=pages,
                )
                indexed_count = indexing_service.index_chunks(chunks)

                await documents_repo.update_security_scan(
                    document_id=doc.id,
                    owner_id=owner_id,
                    trust_data=trust_data,
                    raw_signals=raw_signals,
                    new_status="indexed",
                    page_count=len(pages),
                )
                await documents_repo.update_status(
                    document_id=doc.id,
                    owner_id=owner_id,
                    status="indexed",
                    chunk_count=indexed_count,
                )
            elif scan_result.policy_decision == "review":
                # Suspicious -> Block indexing and set to 'review' status
                logger.warning(
                    "Document held for review; indexing blocked",
                    extra={"document_id": doc.id, "signals_count": scan_result.signals_count},
                )
                await documents_repo.update_security_scan(
                    document_id=doc.id,
                    owner_id=owner_id,
                    trust_data=trust_data,
                    raw_signals=raw_signals,
                    new_status="review",
                    page_count=len(pages),
                )
            else:
                # Quarantined -> Block indexing and set to 'quarantined' status
                logger.warning(
                    "Document quarantined; indexing blocked",
                    extra={"document_id": doc.id, "signals_count": scan_result.signals_count},
                )
                await documents_repo.update_security_scan(
                    document_id=doc.id,
                    owner_id=owner_id,
                    trust_data=trust_data,
                    raw_signals=raw_signals,
                    new_status="quarantined",
                    page_count=len(pages),
                )

            # Fetch fresh state
            updated_doc = await documents_repo.get_by_id(doc.id, owner_id)
            if not updated_doc:
                raise DocumentIngestionError("Document could not be retrieved after processing", doc_id=doc.id)

            return updated_doc

        except (PDFExtractionError, Exception) as exc:
            err_msg = str(exc)
            logger.warning(
                "Document ingestion failed",
                extra={"document_id": doc.id, "owner_id": owner_id, "error": err_msg},
            )
            # Record failure in MongoDB
            await documents_repo.update_status(
                document_id=doc.id,
                owner_id=owner_id,
                status="failed",
                error_message=err_msg,
            )
            raise DocumentIngestionError(err_msg, doc_id=doc.id) from exc

    async def get_document(self, document_id: str, owner_id: str) -> DocumentInDB:
        """Fetch a document by ID and verify ownership."""
        doc = await documents_repo.get_by_id(document_id=document_id, owner_id=owner_id)
        if not doc:
            raise DocumentNotFoundError(f"Document {document_id} not found")
        return doc

    async def list_documents(
        self,
        owner_id: str,
        limit: int = 50,
        skip: int = 0,
    ) -> Tuple[list[DocumentInDB], int]:
        """Fetch paginated documents owned by the specified user."""
        return await documents_repo.list_by_owner(owner_id=owner_id, limit=limit, skip=skip)

    async def list_review_queue(
        self,
        owner_id: str,
        limit: int = 50,
        skip: int = 0,
    ) -> Tuple[list[DocumentInDB], int]:
        """Fetch documents awaiting security review."""
        return await documents_repo.list_review_queue(owner_id=owner_id, limit=limit, skip=skip)

    async def get_security_details(self, document_id: str, owner_id: str) -> dict[str, Any]:
        """Fetch full security scan findings and detection signals for a document."""
        doc = await documents_repo.get_security_details(document_id=document_id, owner_id=owner_id)
        if not doc:
            raise DocumentNotFoundError(f"Document {document_id} not found")

        trust = doc.get("trust", {})
        signals = doc.get("security_signals", [])

        return {
            "document_id": doc["_id"],
            "original_filename": doc.get("original_filename", ""),
            "status": doc.get("status", "unknown"),
            "risk_level": trust.get("risk_level", "low"),
            "policy_decision": trust.get("policy_decision", "allow"),
            "signals_count": len(signals),
            "signals": signals,
            "scanner_version": trust.get("scanner_version", "1.0.0"),
            "scanned_at": trust.get("scanned_at"),
            "summary": f"Security status: {trust.get('policy_decision', 'allow')}. {len(signals)} signal(s) recorded.",
        }

    async def review_document(
        self,
        document_id: str,
        reviewer_id: str,
        reviewer_role: str,
        decision: str,
        notes: Optional[str] = None,
        correlation_id: Optional[str] = None,
    ) -> DocumentInDB:
        """
        Manually review a document held in 'review' or existing status.

        Args:
            document_id: Target document ID.
            reviewer_id: Authenticated reviewer ID.
            reviewer_role: User role ('admin' or 'user').
            decision: 'approve' to index, 'quarantine' to block.
            notes: Optional review commentary.
            correlation_id: Request correlation ID.
        """
        # Fetch document
        doc = await documents_repo.get_by_id(document_id=document_id, owner_id=reviewer_id)
        if not doc and reviewer_role != "admin":
            raise DocumentNotFoundError(f"Document {document_id} not found")

        if not doc:
            # If admin, fetch without owner_id constraint
            raw_doc = await documents_repo.collection.find_one({"_id": document_id, "status": {"$ne": "deleted"}})
            if not raw_doc:
                raise DocumentNotFoundError(f"Document {document_id} not found")
            doc = DocumentInDB(**raw_doc)

        # Enforce authorization
        if doc.owner_id != reviewer_id and reviewer_role != "admin":
            raise DocumentAccessDeniedError("You do not have permission to review this document")

        decision_clean = decision.lower().strip()
        if decision_clean not in {"approve", "quarantine"}:
            raise ValueError("Review decision must be either 'approve' or 'quarantine'")

        chunks_indexed = 0
        chunks_deleted = 0

        if decision_clean == "approve":
            # If document was not indexed, extract, chunk, and index it now
            if doc.status in {"review", "quarantined", "uploaded", "processing"}:
                file_path = self.storage.get_file_path(doc.storage_key)
                pages = pdf_service.extract_text_by_page(file_path)
                chunks = chunking_service.chunk_document_pages(
                    document_id=doc.id,
                    owner_id=doc.owner_id,
                    source_filename=doc.original_filename,
                    pages=pages,
                )
                chunks_indexed = indexing_service.index_chunks(chunks)

            # Update trust to allow
            new_trust = doc.trust.model_dump()
            new_trust["status"] = "allow"
            new_trust["policy_decision"] = "allow"
            new_trust["reviewed_by"] = reviewer_id
            new_trust["review_notes"] = notes

            await documents_repo.update_status(
                document_id=doc.id,
                owner_id=doc.owner_id,
                status="indexed",
                chunk_count=chunks_indexed or doc.chunk_count,
                trust=new_trust,
            )

            await security_events_repo.record_event(
                event_type="document_approved",
                severity="low",
                decision="allow",
                reason_code="MANUAL_OVERRIDE",
                resource_type="document",
                resource_id=doc.id,
                owner_id=doc.owner_id,
                actor_user_id=reviewer_id,
                correlation_id=correlation_id,
                safe_metadata={"notes": notes, "chunks_indexed": chunks_indexed},
            )
        else:
            # Quarantine decision -> Purge any existing vectors in ChromaDB
            try:
                chunks_deleted = indexing_service.delete_document_vectors(
                    document_id=doc.id,
                    owner_id=doc.owner_id,
                )
            except Exception as exc:  # noqa: BLE001
                logger.warning("Error purging vectors on quarantine", extra={"error": str(exc)})

            new_trust = doc.trust.model_dump()
            new_trust["status"] = "quarantined"
            new_trust["policy_decision"] = "quarantined"
            new_trust["reviewed_by"] = reviewer_id
            new_trust["review_notes"] = notes

            await documents_repo.update_status(
                document_id=doc.id,
                owner_id=doc.owner_id,
                status="quarantined",
                chunk_count=0,
                trust=new_trust,
            )

            await security_events_repo.record_event(
                event_type="document_quarantined",
                severity="high",
                decision="quarantined",
                reason_code="MANUAL_OVERRIDE",
                resource_type="document",
                resource_id=doc.id,
                owner_id=doc.owner_id,
                actor_user_id=reviewer_id,
                correlation_id=correlation_id,
                safe_metadata={"notes": notes, "chunks_purged": chunks_deleted},
            )

        updated_doc = await documents_repo.get_by_id(doc.id, doc.owner_id)
        return updated_doc

    async def rescan_document(
        self,
        document_id: str,
        owner_id: str,
        correlation_id: Optional[str] = None,
    ) -> ScanResult:
        """
        Re-evaluate an existing document using the security scanner.
        Enforces updated trust decisions (e.g. if newly flagged, purges vectors).
        """
        doc = await documents_repo.get_by_id(document_id=document_id, owner_id=owner_id)
        if not doc:
            raise DocumentNotFoundError(f"Document {document_id} not found")

        file_path = self.storage.get_file_path(doc.storage_key)
        pages = pdf_service.extract_text_by_page(file_path)

        scan_result = security_scanner.scan_document(
            document_id=doc.id,
            owner_id=owner_id,
            filename=doc.original_filename,
            pages=pages,
        )

        trust_data = {
            "status": scan_result.policy_decision,
            "risk_level": scan_result.risk_level,
            "signals": [s.pattern_name for s in scan_result.signals],
            "scanner_version": scan_result.scanner_version,
            "classifier_version": scan_result.classifier_version,
            "scanned_at": scan_result.scanned_at,
            "policy_decision": scan_result.policy_decision,
        }
        raw_signals = [s.model_dump() for s in scan_result.signals]

        # Record audit event
        await security_events_repo.record_event(
            event_type="document_rescanned",
            severity=scan_result.risk_level,
            decision=scan_result.policy_decision,
            reason_code=scan_result.reason_code,
            resource_type="document",
            resource_id=doc.id,
            owner_id=owner_id,
            actor_user_id=owner_id,
            correlation_id=correlation_id,
            safe_metadata={"signals_count": scan_result.signals_count},
        )

        # Enforce transitions
        if scan_result.policy_decision == "quarantined":
            # If document was previously indexed, purge vectors from ChromaDB immediately!
            indexing_service.delete_document_vectors(document_id=doc.id, owner_id=owner_id)
            await documents_repo.update_security_scan(
                document_id=doc.id,
                owner_id=owner_id,
                trust_data=trust_data,
                raw_signals=raw_signals,
                new_status="quarantined",
                page_count=len(pages),
            )
            await documents_repo.update_status(document_id=doc.id, owner_id=owner_id, status="quarantined", chunk_count=0)
        elif scan_result.policy_decision == "review":
            # Remove from active vector index if it was previously indexed
            indexing_service.delete_document_vectors(document_id=doc.id, owner_id=owner_id)
            await documents_repo.update_security_scan(
                document_id=doc.id,
                owner_id=owner_id,
                trust_data=trust_data,
                raw_signals=raw_signals,
                new_status="review",
                page_count=len(pages),
            )
            await documents_repo.update_status(document_id=doc.id, owner_id=owner_id, status="review", chunk_count=0)
        else:
            # Allow decision -> Ensure it is indexed
            chunks = chunking_service.chunk_document_pages(
                document_id=doc.id,
                owner_id=owner_id,
                source_filename=doc.original_filename,
                pages=pages,
            )
            indexed_count = indexing_service.index_chunks(chunks)
            await documents_repo.update_security_scan(
                document_id=doc.id,
                owner_id=owner_id,
                trust_data=trust_data,
                raw_signals=raw_signals,
                new_status="indexed",
                page_count=len(pages),
            )
            await documents_repo.update_status(document_id=doc.id, owner_id=owner_id, status="indexed", chunk_count=indexed_count)

        return scan_result

    async def delete_document(self, document_id: str, owner_id: str) -> int:
        """Delete document, vector embeddings, and physical disk file."""
        doc = await documents_repo.get_by_id(document_id=document_id, owner_id=owner_id)
        if not doc:
            raise DocumentNotFoundError(f"Document {document_id} not found")

        # 1. Mark status 'deleting'
        await documents_repo.mark_deleting(document_id=document_id, owner_id=owner_id)

        # 2. Delete ChromaDB vectors
        chunks_deleted = 0
        try:
            chunks_deleted = indexing_service.delete_document_vectors(
                document_id=document_id,
                owner_id=owner_id,
            )
        except Exception as exc:  # noqa: BLE001
            logger.error(
                "Error deleting vectors during document purge",
                extra={"document_id": document_id, "error": str(exc)},
            )

        # 3. Delete disk file
        try:
            self.storage.delete_file(doc.storage_key)
        except Exception as exc:  # noqa: BLE001
            logger.warning(
                "Error deleting file from disk storage",
                extra={"storage_key": doc.storage_key, "error": str(exc)},
            )

        # 4. Mark status 'deleted' in MongoDB
        await documents_repo.mark_deleted(document_id=document_id, owner_id=owner_id)

        logger.info(
            "Document successfully deleted",
            extra={
                "document_id": document_id,
                "owner_id": owner_id,
                "chunks_purged": chunks_deleted,
            },
        )
        return chunks_deleted


document_service = DocumentService()
