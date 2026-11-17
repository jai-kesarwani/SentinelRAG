"""
SentinelRAG — Core RAG AI Agent Test Suite.

Verifies Phase 4 requirements:
- Conversation creation, listing, retrieval, and deletion
- Authentication and cross-user conversation isolation
- Tenant-scoped retrieval & exclusion of cross-tenant or unapproved chunks
- Empty retrieval / insufficient context handling
- Grounded Q&A with mocked Gemini provider and verified citations
- Message persistence and chronological ordering
"""
from __future__ import annotations

import uuid
from unittest.mock import AsyncMock, patch

import pytest
import pymupdf
from httpx import ASGITransport, AsyncClient

from app.main import app
from app.services.llm_provider import BaseLLMProvider, LLMQuotaExceededError, LLMUnavailableError
from app.services.rag_service import rag_service
from app.services.retrieval_service import RetrievedChunk, retrieval_service


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
    """Helper to generate a valid in-memory PDF."""
    doc = pymupdf.open()
    for text in pages_text:
        page = doc.new_page(width=595, height=842)
        page.insert_text((50, 72), text, fontsize=12)
    pdf_bytes = doc.tobytes()
    doc.close()
    return pdf_bytes


async def register_and_get_auth(client: AsyncClient, prefix: str = "rag_user") -> tuple[dict[str, str], str]:
    """Helper to register user and return (auth_headers, user_id)."""
    email = f"{prefix}_{uuid.uuid4().hex[:8]}@example.com"
    pwd = "SecurePassword123!"
    reg_res = await client.post(
        "/api/v1/auth/register",
        json={"email": email, "password": pwd, "display_name": "RAG Tester"},
    )
    assert reg_res.status_code == 201
    user_id = reg_res.json()["data"]["id"]

    login_res = await client.post(
        "/api/v1/auth/login",
        json={"email": email, "password": pwd},
    )
    assert login_res.status_code == 200
    token = login_res.json()["data"]["access_token"]
    return {"Authorization": f"Bearer {token}"}, user_id


class MockLLM(BaseLLMProvider):
    """Deterministic mock LLM provider for tests."""

    def __init__(self, answer_to_return: str):
        self.answer_to_return = answer_to_return
        self.call_count = 0

    async def generate_response(
        self,
        system_prompt: str,
        user_prompt: str,
        temperature: float = 0.2,
        max_output_tokens: int = 1024,
    ) -> str:
        self.call_count += 1
        return self.answer_to_return


# --------------------------------------------------------------------------- #
# Conversation Lifecycle & Isolation Tests
# --------------------------------------------------------------------------- #

@pytest.mark.asyncio
async def test_conversation_lifecycle_and_isolation(api_client):
    """Verify conversation creation, listing, detail retrieval, isolation, and deletion."""
    headers_a, user_a_id = await register_and_get_auth(api_client, "user_conv_a")
    headers_b, user_b_id = await register_and_get_auth(api_client, "user_conv_b")

    # 1. User A creates conversation
    create_res = await api_client.post(
        "/api/v1/chat/conversations",
        headers=headers_a,
        json={"title": "Security Guidelines Q&A"},
    )
    assert create_res.status_code == 201
    conv_data = create_res.json()["data"]
    conv_id = conv_data["id"]
    assert conv_data["title"] == "Security Guidelines Q&A"
    assert conv_data["owner_id"] == user_a_id

    # 2. User A lists conversations -> sees 1
    list_res_a = await api_client.get("/api/v1/chat/conversations", headers=headers_a)
    assert list_res_a.status_code == 200
    assert list_res_a.json()["data"]["total"] >= 1
    assert any(c["id"] == conv_id for c in list_res_a.json()["data"]["conversations"])

    # 3. User B lists conversations -> does NOT see User A's conversation
    list_res_b = await api_client.get("/api/v1/chat/conversations", headers=headers_b)
    assert list_res_b.status_code == 200
    assert not any(c["id"] == conv_id for c in list_res_b.json()["data"]["conversations"])

    # 4. User B attempts to access User A's conversation directly -> 404
    get_res_b = await api_client.get(f"/api/v1/chat/conversations/{conv_id}", headers=headers_b)
    assert get_res_b.status_code == 404

    # 5. User B attempts to post message to User A's conversation -> 404
    msg_res_b = await api_client.post(
        f"/api/v1/chat/conversations/{conv_id}/messages",
        headers=headers_b,
        json={"content": "Unauthorized message attempt"},
    )
    assert msg_res_b.status_code == 404

    # 6. User B attempts to delete User A's conversation -> 404
    del_res_b = await api_client.delete(f"/api/v1/chat/conversations/{conv_id}", headers=headers_b)
    assert del_res_b.status_code == 404

    # 7. User A deletes conversation -> 200
    del_res_a = await api_client.delete(f"/api/v1/chat/conversations/{conv_id}", headers=headers_a)
    assert del_res_a.status_code == 200
    assert del_res_a.json()["data"]["deleted"] is True

    # 8. User A gets deleted conversation -> 404
    get_res_a = await api_client.get(f"/api/v1/chat/conversations/{conv_id}", headers=headers_a)
    assert get_res_a.status_code == 404


@pytest.mark.asyncio
async def test_unauthenticated_requests_rejected(api_client):
    """All chat endpoints must reject unauthenticated requests with 401."""
    res1 = await api_client.get("/api/v1/chat/conversations")
    assert res1.status_code == 401

    res2 = await api_client.post("/api/v1/chat/conversations", json={"title": "Test"})
    assert res2.status_code == 401

    res3 = await api_client.post("/api/v1/chat/conversations/fake_id/messages", json={"content": "Hi"})
    assert res3.status_code == 401


# --------------------------------------------------------------------------- #
# RAG Question Answering & Retrieval Tests
# --------------------------------------------------------------------------- #

@pytest.mark.asyncio
async def test_rag_empty_retrieval_insufficient_context(api_client):
    """When no documents exist, assistant honestly reports insufficient context."""
    headers, _ = await register_and_get_auth(api_client, "user_empty_rag")

    # Create conversation
    create_res = await api_client.post("/api/v1/chat/conversations", headers=headers)
    conv_id = create_res.json()["data"]["id"]

    # Ask question with no documents uploaded
    msg_res = await api_client.post(
        f"/api/v1/chat/conversations/{conv_id}/messages",
        headers=headers,
        json={"content": "What is the project budget limit?"},
    )
    assert msg_res.status_code == 200
    data = msg_res.json()["data"]

    assert data["grounded"] is False
    assert data["retrieved_chunk_count"] == 0
    assert len(data["citations"]) == 0
    assert "could not find any relevant information" in data["message"]["content"].lower()

    # Message must be persisted
    get_res = await api_client.get(f"/api/v1/chat/conversations/{conv_id}", headers=headers)
    messages = get_res.json()["data"]["messages"]
    assert len(messages) == 2  # 1 user + 1 assistant
    assert messages[0]["role"] == "user"
    assert messages[1]["role"] == "assistant"


@pytest.mark.asyncio
async def test_rag_grounded_answer_with_citations(api_client):
    """Uploaded PDF provides context; assistant answers and provides verified citations."""
    headers, user_id = await register_and_get_auth(api_client, "user_grounded")

    # 1. Upload knowledge PDF
    pdf_text = "The SentinelRAG deployment architecture mandates that all worker nodes must run Linux kernel 6.1 or higher."
    pdf_bytes = create_sample_pdf_bytes([pdf_text])
    files = {"file": ("deployment_spec.pdf", pdf_bytes, "application/pdf")}
    upload_res = await api_client.post("/api/v1/documents/upload", headers=headers, files=files)
    assert upload_res.status_code == 201
    doc_id = upload_res.json()["data"]["id"]

    # 2. Create conversation
    conv_res = await api_client.post("/api/v1/chat/conversations", headers=headers)
    conv_id = conv_res.json()["data"]["id"]

    # 3. Patch LLM provider with deterministic mock
    mock_answer = (
        "Based on [Source 1], the SentinelRAG deployment architecture requires all worker nodes "
        "to run Linux kernel 6.1 or higher."
    )
    mock_llm = MockLLM(mock_answer)

    with patch.object(rag_service, "llm", mock_llm):
        msg_res = await api_client.post(
            f"/api/v1/chat/conversations/{conv_id}/messages",
            headers=headers,
            json={"content": "What Linux kernel version is required for worker nodes?"},
        )
        assert msg_res.status_code == 200
        data = msg_res.json()["data"]

        assert data["grounded"] is True
        assert data["retrieved_chunk_count"] >= 1
        assert len(data["citations"]) >= 1

        citation = data["citations"][0]
        assert citation["document_id"] == doc_id
        assert citation["source_filename"] == "deployment_spec.pdf"
        assert citation["page_number"] == 1
        assert "Linux kernel 6.1" in citation["excerpt"]
        assert mock_llm.call_count == 1


@pytest.mark.asyncio
async def test_retrieval_cross_tenant_isolation(api_client):
    """User B cannot retrieve User A's document chunks even with matching keywords."""
    headers_a, _ = await register_and_get_auth(api_client, "tenant_a")
    headers_b, user_b_id = await register_and_get_auth(api_client, "tenant_b")

    # User A uploads secret financial file
    pdf_bytes = create_sample_pdf_bytes(["Confidential Q4 Secret Revenue: Exactly $42.5 Million USD for User A."])
    files = {"file": ("user_a_secrets.pdf", pdf_bytes, "application/pdf")}
    upload_res = await api_client.post("/api/v1/documents/upload", headers=headers_a, files=files)
    assert upload_res.status_code == 201

    # User B queries retrieval service directly for the exact secret keyword
    retrieved_chunks = await retrieval_service.retrieve_relevant_chunks(
        query="Confidential Q4 Secret Revenue",
        owner_id=user_b_id,  # User B identity
        top_k=5,
    )

    # Retrieval MUST return 0 chunks for User B
    assert len(retrieved_chunks) == 0


@pytest.mark.asyncio
async def test_rag_llm_error_handling(api_client):
    """When LLM provider raises an error (e.g. rate limit), RAG handles it gracefully."""
    headers, _ = await register_and_get_auth(api_client, "user_error_test")

    # Upload document so retrieval succeeds
    pdf_bytes = create_sample_pdf_bytes(["Test document content."])
    files = {"file": ("test.pdf", pdf_bytes, "application/pdf")}
    await api_client.post("/api/v1/documents/upload", headers=headers, files=files)

    # Create conversation
    conv_res = await api_client.post("/api/v1/chat/conversations", headers=headers)
    conv_id = conv_res.json()["data"]["id"]

    # Mock LLM provider raising Quota Exceeded
    failing_llm = AsyncMock()
    failing_llm.generate_response.side_effect = LLMQuotaExceededError()

    with patch.object(rag_service, "llm", failing_llm):
        msg_res = await api_client.post(
            f"/api/v1/chat/conversations/{conv_id}/messages",
            headers=headers,
            json={"content": "What is in the test document?"},
        )
        assert msg_res.status_code == 200
        data = msg_res.json()["data"]

        assert data["grounded"] is False
        assert "quota exceeded" in data["message"]["content"].lower()

