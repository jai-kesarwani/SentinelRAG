"""
SentinelRAG — Security Center & Analytics Schemas.

Pydantic v2 schemas for overview metrics, activity timelines, threat distributions,
attack simulation performance, and filtered security event exploration.
"""
from __future__ import annotations

from datetime import datetime
from typing import Any, Optional

from pydantic import BaseModel, ConfigDict, Field


class SecurityOverviewMetrics(BaseModel):
    """Cumulative overview metrics for security center dashboard."""

    total_events: int = 0
    blocked_queries: int = 0
    document_threats_detected: int = 0
    output_interventions: int = 0
    total_simulations: int = 0
    simulated_attacks_prevented: int = 0
    simulated_attacks_succeeded: int = 0
    simulation_block_rate_percent: float = 0.0


class TimelineDataPoint(BaseModel):
    """Aggregated security event counts for a specific time interval bucket."""

    timestamp: str
    label: str
    count: int = 0
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0


class SecurityActivityResponse(BaseModel):
    """Activity timeline response over selected period."""

    time_range: str
    total_events: int
    timeline: list[TimelineDataPoint] = Field(default_factory=list)


class CategoryCount(BaseModel):
    """Itemized event count and share per threat category."""

    category: str
    label: str
    count: int = 0
    percentage: float = 0.0


class SeverityCount(BaseModel):
    """Itemized event count and share per severity rating."""

    severity: str
    count: int = 0
    percentage: float = 0.0


class ThreatDistributionResponse(BaseModel):
    """Threat breakdown across attack categories and severities."""

    total_events: int
    categories: list[CategoryCount] = Field(default_factory=list)
    severities: list[SeverityCount] = Field(default_factory=list)
    decisions: dict[str, int] = Field(default_factory=dict)


class SimulationCategoryStat(BaseModel):
    """Simulation outcomes grouped by attack category."""

    category: str
    label: str
    total: int = 0
    blocked: int = 0
    detected_not_blocked: int = 0
    attack_succeeded: int = 0
    inconclusive: int = 0
    error: int = 0
    block_rate_percent: float = 0.0


class SimulationAnalyticsResponse(BaseModel):
    """Comprehensive analytics derived from controlled Attack Simulator runs."""

    total_runs: int = 0
    total_executed: int = 0
    completed_attacks: int = 0
    blocked: int = 0
    detected_not_blocked: int = 0
    attack_succeeded: int = 0
    inconclusive: int = 0
    error: int = 0
    block_rate_percent: float = 0.0
    categories: list[SimulationCategoryStat] = Field(default_factory=list)


class SecurityEventDetailResponse(BaseModel):
    """Safe, auditable representation of an individual security incident."""

    id: str
    owner_id: str
    event_type: str
    category: str
    severity: str
    decision: str
    reason_code: str
    resource_type: str
    resource_id: Optional[str] = None
    detector: dict[str, Any] = Field(default_factory=dict)
    safe_metadata: dict[str, Any] = Field(default_factory=dict)
    correlation_id: Optional[str] = None
    created_at: datetime

    model_config = ConfigDict(populate_by_name=True)


class SecurityEventListResponse(BaseModel):
    """Paginated security event list for exploration and audit."""

    events: list[SecurityEventDetailResponse]
    total: int
    limit: int
    skip: int

