"""
SentinelRAG — Documents Management API Endpoints.

Endpoints:
  POST   /api/v1/documents/upload          — Authenticated PDF upload, security screening & indexing
  POST   /api/v1/documents                 — Alias for PDF upload
  GET    /api/v1/documents                 — List authenticated user's uploaded documents
  GET    /api/v1/documents/review/queue    — List documents awaiting security review
  GET    /api/v1/documents/{id}            — Retrieve document details and ingestion status
  GET    /api/v1/documents/{id}/security   — Retrieve security scan findings, risk score & signals
  POST   /api/v1/documents/{id}/review     — Approve or quarantine document held in review
  POST   /api/v1/documents/{id}/rescan     — Re-evaluate document with security scanner
  DELETE /api/v1/documents/{id}            — Purge document, vectors, and disk file
"""
from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, Depends, File, HTTPException, Query, Request, UploadFile, status

from app.api.dependencies import get_current_active_user
from app.models.user import UserInDB
from app.schemas.document import DocumentReviewRequest
from app.services.document_service import (
    DocumentAccessDeniedError,
    DocumentIngestionError,
    DocumentNotFoundError,
    document_service,
)
from app.services.storage_service import StorageValidationError
from app.utils.correlation import get_correlation_id

router = APIRouter(prefix="/documents", tags=["Documents"])


def _envelope(data: dict | list, correlation_id: str) -> dict:
    """Format success response according to standard API envelope."""
    return {"data": data, "meta": {"correlation_id": correlation_id}}


@router.post("/upload", status_code=status.HTTP_201_CREATED)
@router.post("", status_code=status.HTTP_201_CREATED)
async def upload_document(
    request: Request,
    file: UploadFile = File(...),
    current_user: UserInDB = Depends(get_current_active_user),
) -> dict:
    """
    Upload a PDF document, extract text, run security inspection, and index into ChromaDB if allowed.
    Strictly scoped to the authenticated user.
    """
    correlation_id = get_correlation_id(request)

    try:
        doc = await document_service.ingest_document(
            owner_id=current_user.id,
            upload_file=file,
            correlation_id=correlation_id,
        )
        return _envelope(doc.to_public_dict(), correlation_id)
    except StorageValidationError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=exc.message,
        ) from exc
    except DocumentIngestionError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=exc.message,
        ) from exc
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"An unexpected error occurred during document processing: {exc}",
        ) from exc


@router.get("")
async def list_documents(
    request: Request,
    limit: int = Query(default=50, ge=1, le=100),
    skip: int = Query(default=0, ge=0),
    current_user: UserInDB = Depends(get_current_active_user),
) -> dict:
    """
    List all documents owned by the authenticated user.
    Excludes soft-deleted documents.
    """
    correlation_id = get_correlation_id(request)
    docs, total = await document_service.list_documents(
        owner_id=current_user.id,
        limit=limit,
        skip=skip,
    )
    return _envelope(
        {
            "documents": [doc.to_public_dict() for doc in docs],
            "total": total,
        },
        correlation_id,
    )


@router.get("/review/queue")
async def list_review_queue(
    request: Request,
    limit: int = Query(default=50, ge=1, le=100),
    skip: int = Query(default=0, ge=0),
    current_user: UserInDB = Depends(get_current_active_user),
) -> dict:
    """List documents currently in 'review' status awaiting verification."""
    correlation_id = get_correlation_id(request)
    docs, total = await document_service.list_review_queue(
        owner_id=current_user.id,
        limit=limit,
        skip=skip,
    )
    return _envelope(
        {
            "documents": [doc.to_public_dict() for doc in docs],
            "total": total,
        },
        correlation_id,
    )


@router.get("/{document_id}")
async def get_document(
    document_id: str,
    request: Request,
    current_user: UserInDB = Depends(get_current_active_user),
) -> dict:
    """
    Retrieve document details by document ID.
    Enforces tenant boundary: 404 if not found or owned by a different user.
    """
    correlation_id = get_correlation_id(request)
    try:
        doc = await document_service.get_document(
            document_id=document_id,
            owner_id=current_user.id,
        )
        return _envelope(doc.to_public_dict(), correlation_id)
    except DocumentNotFoundError:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Document not found",
        )


@router.get("/{document_id}/security")
async def get_document_security(
    document_id: str,
    request: Request,
    current_user: UserInDB = Depends(get_current_active_user),
) -> dict:
    """
    Retrieve detailed security scan findings, detected signals, and policy decision.
    Enforces tenant boundary: 404 if not found or owned by a different user.
    """
    correlation_id = get_correlation_id(request)
    try:
        details = await document_service.get_security_details(
            document_id=document_id,
            owner_id=current_user.id,
        )
        return _envelope(details, correlation_id)
    except DocumentNotFoundError:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Document not found",
        )


@router.post("/{document_id}/review")
async def review_document(
    document_id: str,
    payload: DocumentReviewRequest,
    request: Request,
    current_user: UserInDB = Depends(get_current_active_user),
) -> dict:
    """
    Manually review a document: approve to allow RAG indexing or quarantine to block.
    Enforces role/owner authorization and logs an immutable audit event.
    """
    correlation_id = get_correlation_id(request)
    try:
        updated_doc = await document_service.review_document(
            document_id=document_id,
            reviewer_id=current_user.id,
            reviewer_role=current_user.role,
            decision=payload.decision,
            notes=payload.notes,
            correlation_id=correlation_id,
        )
        return _envelope(
            {
                "document_id": updated_doc.id,
                "status": updated_doc.status,
                "policy_decision": updated_doc.trust.policy_decision,
                "chunk_count": updated_doc.chunk_count,
                "message": f"Document reviewed successfully. New status: {updated_doc.status}",
            },
            correlation_id,
        )
    except DocumentNotFoundError:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Document not found")
    except DocumentAccessDeniedError as exc:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(exc))
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))


@router.post("/{document_id}/rescan")
async def rescan_document(
    document_id: str,
    request: Request,
    current_user: UserInDB = Depends(get_current_active_user),
) -> dict:
    """
    Trigger a security rescan of an existing document using the latest rule definitions.
    Enforces updated security status and adjusts vector indexing accordingly.
    """
    correlation_id = get_correlation_id(request)
    try:
        scan_result = await document_service.rescan_document(
            document_id=document_id,
            owner_id=current_user.id,
            correlation_id=correlation_id,
        )
        return _envelope(
            {
                "document_id": scan_result.document_id,
                "risk_level": scan_result.risk_level,
                "policy_decision": scan_result.policy_decision,
                "signals_count": scan_result.signals_count,
                "summary": scan_result.summary,
                "message": "Document re-evaluated successfully",
            },
            correlation_id,
        )
    except DocumentNotFoundError:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Document not found")


@router.delete("/{document_id}")
async def delete_document(
    document_id: str,
    request: Request,
    current_user: UserInDB = Depends(get_current_active_user),
) -> dict:
    """
    Delete a document, purge all vector chunks from ChromaDB, and remove the file from storage.
    Enforces tenant boundary: 404 if not found or owned by a different user.
    """
    correlation_id = get_correlation_id(request)
    try:
        chunks_deleted = await document_service.delete_document(
            document_id=document_id,
            owner_id=current_user.id,
        )
        return _envelope(
            {
                "document_id": document_id,
                "deleted": True,
                "chunks_deleted": chunks_deleted,
                "message": "Document and associated vectors deleted successfully",
            },
            correlation_id,
        )
    except DocumentNotFoundError:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Document not found",
        )
