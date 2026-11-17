"""
SentinelRAG — Health Endpoint Tests.

Tests the /api/v1/health and /api/v1/ping endpoints without requiring
live database connections (unit-level API tests with mocked DB state).

For integration tests that require real MongoDB/ChromaDB connections,
see the integration test suite added in Phase 9.
"""
from __future__ import annotations

import pytest
from httpx import ASGITransport, AsyncClient

# Patch DB managers before importing the app so startup does not try real connections
import unittest.mock as mock


@pytest.fixture
def mock_db_managers():
    """Mock the DB managers so tests do not require live connections."""
    with (
        mock.patch(
            "app.db.mongodb.mongodb_manager.connect",
            new_callable=mock.AsyncMock,
        ),
        mock.patch(
            "app.db.chromadb.chromadb_manager.initialize",
        ),
    ):
        yield


@pytest.fixture
async def client(mock_db_managers):
    """Async HTTP client wired to the FastAPI test app."""
    # Import after patching
    from app.main import app

    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://testserver",
    ) as ac:
        yield ac


@pytest.mark.asyncio
async def test_ping_returns_200(client):
    """GET /api/v1/ping should return HTTP 200."""
    response = await client.get("/api/v1/ping")
    assert response.status_code == 200


@pytest.mark.asyncio
async def test_ping_response_envelope(client):
    """GET /api/v1/ping response must include data.pong and meta.correlation_id."""
    response = await client.get("/api/v1/ping")
    body = response.json()
    assert "data" in body
    assert body["data"]["pong"] is True
    assert "meta" in body
    assert "correlation_id" in body["meta"]
    assert len(body["meta"]["correlation_id"]) > 0


@pytest.mark.asyncio
async def test_health_returns_200(client):
    """GET /api/v1/health should return HTTP 200."""
    response = await client.get("/api/v1/health")
    assert response.status_code == 200


@pytest.mark.asyncio
async def test_health_response_structure(client):
    """GET /api/v1/health must include status, version, environment, timestamp."""
    response = await client.get("/api/v1/health")
    body = response.json()
    data = body.get("data", {})
    assert data.get("status") == "healthy"
    assert "version" in data
    assert "environment" in data
    assert "timestamp" in data
    assert "correlation_id" in body.get("meta", {})


@pytest.mark.asyncio
async def test_health_has_correlation_id_header(client):
    """Every response must carry X-Correlation-ID header."""
    response = await client.get("/api/v1/health")
    assert "x-correlation-id" in response.headers


@pytest.mark.asyncio
async def test_unknown_route_returns_404(client):
    """Unknown routes must return 404 with error envelope."""
    response = await client.get("/api/v1/does-not-exist")
    assert response.status_code == 404
    body = response.json()
    assert "error" in body
    assert body["error"]["code"] == "NOT_FOUND"

