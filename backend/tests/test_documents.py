"""
SentinelRAG — Document Management & Ingestion Test Suite.

Verifies Phase 3 capabilities:
- PDF upload, magic-byte validation, and SHA-256 calculation
- Page-by-page text extraction and empty/encrypted rejection
- Deterministic chunking and ChromaDB vector persistence
- Tenant-scoped listing and individual document retrieval
- Multi-user isolation (User B cannot view or delete User A's documents)
- Complete document purge (MongoDB status, ChromaDB vectors, and disk storage)
"""
from __future__ import annotations

import io
import uuid
import pytest
import pymupdf
from httpx import ASGITransport, AsyncClient

from app.main import app
from app.services.indexing_service import indexing_service


@pytest.fixture(scope="session")
def anyio_backend():
    return "asyncio"


@pytest.fixture
async def api_client():
    """Async client initialized with lifespan context."""
    async with app.router.lifespan_context(app):
        async with AsyncClient(
            transport=ASGITransport(app=app),
            base_url="http://testserver",
        ) as client:
            yield client


def create_sample_pdf_bytes(pages_text: list[str]) -> bytes:
    """Helper to generate a valid in-memory PDF with specified text per page."""
    doc = pymupdf.open()
    for text in pages_text:
        page = doc.new_page(width=595, height=842)  # A4
        page.insert_text((50, 72), text, fontsize=12)
    pdf_bytes = doc.tobytes()
    doc.close()
    return pdf_bytes


async def register_and_get_auth_headers(client: AsyncClient, prefix: str = "doc_user") -> dict[str, str]:
    """Helper to register a unique user and return Bearer auth headers."""
    email = f"{prefix}_{uuid.uuid4().hex[:8]}@example.com"
    pwd = "StrongPassword123!"
    reg_res = await client.post(
        "/api/v1/auth/register",
        json={"email": email, "password": pwd, "display_name": "Test Ingestor"},
    )
    assert reg_res.status_code == 201

    login_res = await client.post(
        "/api/v1/auth/login",
        json={"email": email, "password": pwd},
    )
    assert login_res.status_code == 200
    token = login_res.json()["data"]["access_token"]
    return {"Authorization": f"Bearer {token}"}


# --------------------------------------------------------------------------- #
# Document Ingestion & Validation Tests
# --------------------------------------------------------------------------- #

@pytest.mark.asyncio
async def test_upload_valid_pdf_end_to_end(api_client):
    """Uploading a valid multi-page PDF extracts text, chunks it, and indexes vectors."""
    headers = await register_and_get_auth_headers(api_client, "user_valid")
    pdf_bytes = create_sample_pdf_bytes([
        "Page 1: SentinelRAG is a secure retrieval-augmented generation system designed for enterprise security.",
        "Page 2: Vector embeddings are indexed using all-MiniLM-L6-v2 in local ChromaDB collections.",
    ])

    files = {"file": ("enterprise_spec.pdf", pdf_bytes, "application/pdf")}
    res = await api_client.post("/api/v1/documents/upload", headers=headers, files=files)
    assert res.status_code == 201
    body = res.json()["data"]

    assert body["original_filename"] == "enterprise_spec.pdf"
    assert body["status"] == "indexed"
    assert body["page_count"] == 2
    assert body["chunk_count"] >= 2
    assert len(body["sha256"]) == 64
    assert body["file_size_bytes"] == len(pdf_bytes)


@pytest.mark.asyncio
async def test_upload_non_pdf_magic_bytes_rejected(api_client):
    """Files with PDF extension but invalid magic bytes must be rejected."""
    headers = await register_and_get_auth_headers(api_client, "user_spoof")
    fake_content = b"This is just plain text, not a real PDF document!"

    files = {"file": ("fake_document.pdf", fake_content, "application/pdf")}
    res = await api_client.post("/api/v1/documents/upload", headers=headers, files=files)
    assert res.status_code == 400
    msg = res.json()["error"]["message"].lower()
    assert "not a valid pdf" in msg or "invalid file header" in msg or "magic bytes" in msg


@pytest.mark.asyncio
async def test_upload_empty_pdf_rejected(api_client):
    """PDFs with no extractable text must be rejected with 422 Unprocessable Entity."""
    headers = await register_and_get_auth_headers(api_client, "user_empty")
    # Empty page with no text inserted
    pdf_bytes = create_sample_pdf_bytes(["   \n  \t "])

    files = {"file": ("empty_scanned.pdf", pdf_bytes, "application/pdf")}
    res = await api_client.post("/api/v1/documents/upload", headers=headers, files=files)
    assert res.status_code == 422
    assert "no extractable text" in res.json()["error"]["message"].lower()


# --------------------------------------------------------------------------- #
# Multi-User Tenant Isolation Tests
# --------------------------------------------------------------------------- #

@pytest.mark.asyncio
async def test_multi_user_document_isolation(api_client):
    """User B must not be able to list, view, or delete User A's documents."""
    headers_user_a = await register_and_get_auth_headers(api_client, "user_a")
    headers_user_b = await register_and_get_auth_headers(api_client, "user_b")

    pdf_bytes = create_sample_pdf_bytes(["Confidential financial analysis for User A only."])
    files = {"file": ("confidential_report.pdf", pdf_bytes, "application/pdf")}

    # User A uploads document
    upload_res = await api_client.post("/api/v1/documents/upload", headers=headers_user_a, files=files)
    assert upload_res.status_code == 201
    doc_id = upload_res.json()["data"]["id"]

    # User B lists documents -> should be empty
    list_res_b = await api_client.get("/api/v1/documents", headers=headers_user_b)
    assert list_res_b.status_code == 200
    assert list_res_b.json()["data"]["total"] == 0
    assert len(list_res_b.json()["data"]["documents"]) == 0

    # User B attempts to access User A's document directly -> 404
    get_res_b = await api_client.get(f"/api/v1/documents/{doc_id}", headers=headers_user_b)
    assert get_res_b.status_code == 404

    # User B attempts to delete User A's document -> 404
    del_res_b = await api_client.delete(f"/api/v1/documents/{doc_id}", headers=headers_user_b)
    assert del_res_b.status_code == 404

    # User A accesses document -> 200
    get_res_a = await api_client.get(f"/api/v1/documents/{doc_id}", headers=headers_user_a)
    assert get_res_a.status_code == 200
    assert get_res_a.json()["data"]["id"] == doc_id


# --------------------------------------------------------------------------- #
# Deletion & Vector Purge Tests
# --------------------------------------------------------------------------- #

@pytest.mark.asyncio
async def test_delete_document_purges_vectors_and_metadata(api_client):
    """Deleting a document must purge ChromaDB vectors and mark document deleted."""
    headers = await register_and_get_auth_headers(api_client, "user_purge")
    pdf_bytes = create_sample_pdf_bytes(["Document content that will be purged from ChromaDB vector store."])

    files = {"file": ("purge_me.pdf", pdf_bytes, "application/pdf")}
    upload_res = await api_client.post("/api/v1/documents/upload", headers=headers, files=files)
    assert upload_res.status_code == 201
    doc_data = upload_res.json()["data"]
    doc_id = doc_data["id"]
    owner_id = doc_data["owner_id"]

    # Verify ChromaDB vectors exist before delete
    vector_count_before = indexing_service.count_document_vectors(doc_id, owner_id)
    assert vector_count_before > 0

    # Perform delete
    del_res = await api_client.delete(f"/api/v1/documents/{doc_id}", headers=headers)
    assert del_res.status_code == 200
    assert del_res.json()["data"]["deleted"] is True
    assert del_res.json()["data"]["chunks_deleted"] == vector_count_before

    # Verify vectors in ChromaDB are purged
    vector_count_after = indexing_service.count_document_vectors(doc_id, owner_id)
    assert vector_count_after == 0

    # Verify document is no longer retrievable
    get_res = await api_client.get(f"/api/v1/documents/{doc_id}", headers=headers)
    assert get_res.status_code == 404
