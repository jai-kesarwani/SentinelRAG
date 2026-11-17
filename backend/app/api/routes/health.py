"""
SentinelRAG — Health Check Routes.

Endpoints:
  GET /api/v1/health            — application liveness (no DB call)
  GET /api/v1/health/database   — MongoDB connectivity (real ping)
  GET /api/v1/health/vector-store — ChromaDB connectivity (real check)

All responses use the standard envelope:
  {"data": {...}, "meta": {"correlation_id": "..."}}

Health endpoints MUST report actual connection status.
Never return "healthy" if a service is unreachable.
"""
from __future__ import annotations

from datetime import datetime, timezone

from fastapi import APIRouter, Request

from app.db.chromadb import chromadb_manager
from app.db.mongodb import mongodb_manager
from app.core.config import get_settings
from app.utils.correlation import get_correlation_id

router = APIRouter(prefix="/health", tags=["Health"])


def _envelope(data: dict, correlation_id: str) -> dict:
    """Wrap response data in the standard API envelope."""
    return {"data": data, "meta": {"correlation_id": correlation_id}}


@router.get("", summary="Application health")
async def health(request: Request) -> dict:
    """
    Application liveness check.

    Returns basic application metadata without touching any backing services.
    Use /health/database and /health/vector-store for deeper checks.
    """
    settings = get_settings()
    correlation_id = get_correlation_id(request)
    return _envelope(
        {
            "status": "healthy",
            "version": settings.APP_VERSION,
            "environment": settings.APP_ENV,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        },
        correlation_id,
    )


@router.get("/database", summary="MongoDB connectivity check")
async def health_database(request: Request) -> dict:
    """
    MongoDB database health check.

    Performs a real ping to MongoDB and reports the actual connection status.
    Returns "unhealthy" with an error message if MongoDB is unreachable.
    """
    correlation_id = get_correlation_id(request)
    result = await mongodb_manager.health_check()

    data = {
        "service": "mongodb",
        "status": result.get("status", "unhealthy"),
        "latency_ms": result.get("latency_ms"),
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
    if result.get("status") != "healthy":
        data["error"] = result.get("error", "Unknown error")

    return _envelope(data, correlation_id)


@router.get("/vector-store", summary="ChromaDB connectivity check")
async def health_vector_store(request: Request) -> dict:
    """
    ChromaDB vector store health check.

    Lists ChromaDB collections to verify the persistent store is accessible.
    Returns "unhealthy" with an error message if ChromaDB is unreachable.
    """
    correlation_id = get_correlation_id(request)
    result = chromadb_manager.health_check()

    data = {
        "service": "chromadb",
        "status": result.get("status", "unhealthy"),
        "latency_ms": result.get("latency_ms"),
        "collections": result.get("collections", []),
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
    if result.get("status") != "healthy":
        data["error"] = result.get("error", "Unknown error")

    return _envelope(data, correlation_id)

