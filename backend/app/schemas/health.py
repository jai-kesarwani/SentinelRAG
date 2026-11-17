"""
SentinelRAG — Health Check Response Schemas.

Pydantic v2 models for health endpoint responses.
All response data must reflect actual service state.
"""
from __future__ import annotations

from typing import Any, Optional

from pydantic import BaseModel, Field


class ServiceStatus(BaseModel):
    """Status of a single backing service (database, vector store, etc.)."""

    status: str = Field(
        description="One of: healthy, unhealthy, degraded",
        examples=["healthy"],
    )
    latency_ms: Optional[float] = Field(
        default=None,
        description="Round-trip latency in milliseconds, if measured",
    )
    error: Optional[str] = Field(
        default=None,
        description="Error description when status is unhealthy",
    )
    details: Optional[dict[str, Any]] = Field(
        default=None,
        description="Additional service-specific metadata",
    )


class HealthData(BaseModel):
    """Core application health information."""

    status: str = Field(description="Overall status: healthy | degraded | unhealthy")
    version: str = Field(description="Application version string")
    environment: str = Field(description="Deployment environment (development, production, …)")
    timestamp: str = Field(description="UTC ISO-8601 timestamp of this response")


class HealthResponse(BaseModel):
    """
    Envelope for the basic /health endpoint.

    Does not include service-level status to keep the top-level check fast.
    """

    status: str
    version: str
    environment: str
    timestamp: str


class DatabaseHealthData(BaseModel):
    """Health data returned by /health/database."""

    service: str = "mongodb"
    status: str
    latency_ms: Optional[float] = None
    error: Optional[str] = None


class VectorStoreHealthData(BaseModel):
    """Health data returned by /health/vector-store."""

    service: str = "chromadb"
    status: str
    latency_ms: Optional[float] = None
    collections: Optional[list[str]] = None
    error: Optional[str] = None


class ResponseMeta(BaseModel):
    """Standard response metadata included in every API response envelope."""

    correlation_id: str


class ApiResponse(BaseModel):
    """Standard success response envelope used across all API endpoints."""

    data: Any
    meta: ResponseMeta

