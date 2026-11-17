"""
SentinelRAG — Security Center & Analytics API Endpoints.

Endpoints:
  GET /api/v1/security-center/overview             — Key summary KPIs (events, blocked queries, documents, simulations)
  GET /api/v1/security-center/activity             — Time-bucketed security event activity timeline (24h, 7d, 30d, 90d)
  GET /api/v1/security-center/threat-distribution  — Event breakdown across categories, severities, and decisions
  GET /api/v1/security-center/simulation-analytics — Actual simulation verdicts, category breakdown, and block rate
  GET /api/v1/security-center/events               — Filtered, paginated security audit events list
  GET /api/v1/security-center/events/{event_id}    — Safe detailed view of an individual security incident
"""
from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status

from app.api.dependencies import get_current_active_user
from app.models.user import UserInDB
from app.schemas.security_analytics import (
    SecurityActivityResponse,
    SecurityEventDetailResponse,
    SecurityEventListResponse,
    SecurityOverviewMetrics,
    SimulationAnalyticsResponse,
    ThreatDistributionResponse,
)
from app.services.security_analytics_service import security_analytics_service
from app.utils.correlation import get_correlation_id

router = APIRouter(prefix="/security-center", tags=["Security Center & Analytics"])


def _envelope(data: dict | list, correlation_id: str) -> dict:
    """Format success response according to standard API envelope."""
    return {"data": data, "meta": {"correlation_id": correlation_id}}


@router.get("/overview")
async def get_overview_metrics(
    request: Request,
    days: Optional[int] = Query(default=None, ge=1, le=365, description="Optional time window in days"),
    current_user: UserInDB = Depends(get_current_active_user),
) -> dict:
    """Retrieve cumulative Security Center overview metrics for the user."""
    correlation_id = get_correlation_id(request)
    metrics = await security_analytics_service.get_overview_metrics(
        owner_id=current_user.id,
        days=days,
    )
    return _envelope(metrics.model_dump(), correlation_id)


@router.get("/activity")
async def get_activity_timeline(
    request: Request,
    time_range: str = Query(default="7d", pattern="^(24h|7d|30d|90d)$", description="Timeline window"),
    current_user: UserInDB = Depends(get_current_active_user),
) -> dict:
    """Retrieve time-bucketed event frequency timeline (24h, 7d, 30d, 90d)."""
    correlation_id = get_correlation_id(request)
    timeline = await security_analytics_service.get_activity_timeline(
        owner_id=current_user.id,
        time_range=time_range,
    )
    return _envelope(timeline.model_dump(), correlation_id)


@router.get("/threat-distribution")
async def get_threat_distribution(
    request: Request,
    days: Optional[int] = Query(default=30, ge=1, le=365, description="Time window in days"),
    current_user: UserInDB = Depends(get_current_active_user),
) -> dict:
    """Retrieve distribution of threats across categories, severities, and decisions."""
    correlation_id = get_correlation_id(request)
    dist = await security_analytics_service.get_threat_distribution(
        owner_id=current_user.id,
        days=days,
    )
    return _envelope(dist.model_dump(), correlation_id)


@router.get("/simulation-analytics")
async def get_simulation_analytics(
    request: Request,
    current_user: UserInDB = Depends(get_current_active_user),
) -> dict:
    """Retrieve controlled Attack Simulator metrics, category breakdown, and block rate."""
    correlation_id = get_correlation_id(request)
    sim_stats = await security_analytics_service.get_simulation_analytics(
        owner_id=current_user.id,
    )
    return _envelope(sim_stats.model_dump(), correlation_id)


@router.get("/events")
async def list_security_events(
    request: Request,
    category: Optional[str] = Query(default=None, description="Category filter"),
    severity: Optional[str] = Query(default=None, description="Severity filter (low, medium, high, critical)"),
    decision: Optional[str] = Query(default=None, description="Decision filter (allow, block, review, quarantined, sanitize)"),
    event_type: Optional[str] = Query(default=None, description="Specific event_type filter"),
    search: Optional[str] = Query(default=None, description="Text search on reason code or resource ID"),
    days: Optional[int] = Query(default=None, ge=1, le=365, description="Days filter"),
    limit: int = Query(default=50, ge=1, le=100),
    skip: int = Query(default=0, ge=0),
    current_user: UserInDB = Depends(get_current_active_user),
) -> dict:
    """List filtered, paginated security audit events."""
    correlation_id = get_correlation_id(request)
    events_res = await security_analytics_service.list_events_filtered(
        owner_id=current_user.id,
        category=category,
        severity=severity,
        decision=decision,
        event_type=event_type,
        search=search,
        days=days,
        limit=limit,
        skip=skip,
    )
    return _envelope(events_res.model_dump(), correlation_id)


@router.get("/events/{event_id}")
async def get_security_event_detail(
    event_id: str,
    request: Request,
    current_user: UserInDB = Depends(get_current_active_user),
) -> dict:
    """Retrieve detailed safe view of an individual security incident."""
    correlation_id = get_correlation_id(request)
    event_detail = await security_analytics_service.get_event_detail(
        event_id=event_id,
        owner_id=current_user.id,
    )
    if not event_detail:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Security event not found or does not belong to you.",
        )
    return _envelope(event_detail.model_dump(), correlation_id)
