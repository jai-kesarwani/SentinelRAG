"""
SentinelRAG — Document Schemas.

Pydantic v2 schemas for document upload, metadata responses, and deletion.
"""
from __future__ import annotations

from datetime import datetime
from typing import Any, Optional

from pydantic import BaseModel, ConfigDict, Field


class DocumentTrustResponse(BaseModel):
    status: str
    risk_level: str
    signals: list[str] = Field(default_factory=list)
    policy_decision: str


class DocumentResponse(BaseModel):
    """Public document metadata response."""

    id: str = Field(alias="_id", default="")
    owner_id: str
    original_filename: str
    file_size_bytes: int
    mime_type: str = "application/pdf"
    status: str
    page_count: int = 0
    chunk_count: int = 0
    sha256: str
    error_message: Optional[str] = None
    trust: Optional[DocumentTrustResponse] = None
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(populate_by_name=True)


class DocumentListResponse(BaseModel):
    """Paginated or bounded list of documents."""

    documents: list[DocumentResponse]
    total: int


class DocumentDeleteResponse(BaseModel):
    """Response returned upon document deletion."""

    document_id: str
    deleted: bool = True
    chunks_deleted: int = 0
    message: str = "Document and associated vectors deleted successfully"



# ------------------------------------------------------------------ #
# Phase 5: Document Security Inspection Schemas
# ------------------------------------------------------------------ #

class SecuritySignalResponse(BaseModel):
    """Detection signal flagged during document security scanning."""

    signal_id: str
    category: str
    pattern_name: str
    severity: str
    confidence: str
    page_number: int
    matched_snippet: str
    description: str


class DocumentSecurityDetailsResponse(BaseModel):
    """Comprehensive security findings and signals for a document."""

    document_id: str
    original_filename: str
    status: str
    risk_level: str
    policy_decision: str
    signals_count: int
    signals: list[SecuritySignalResponse] = Field(default_factory=list)
    scanner_version: str
    scanned_at: Optional[datetime] = None
    summary: str


class DocumentReviewRequest(BaseModel):
    """Request payload to manually approve or quarantine a document held in review."""

    decision: str = Field(description="'approve' to index document, 'quarantine' to block")
    notes: Optional[str] = Field(default=None, max_length=500)


class DocumentReviewResponse(BaseModel):
    """Response returned upon review decision."""

    document_id: str
    status: str
    policy_decision: str
    chunks_indexed: int = 0
    chunks_deleted: int = 0
    message: str


class DocumentRescanResponse(BaseModel):
    """Response returned upon re-evaluating a document with the security scanner."""

    document_id: str
    status: str
    risk_level: str
    policy_decision: str
    signals_count: int
    message: str
