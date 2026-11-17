"""
SentinelRAG — Attack Simulator Pydantic Schemas.

Request and response contracts for attack scenarios, execution runs, and test history.
"""
from __future__ import annotations

from datetime import datetime
from typing import Any, Optional

from pydantic import BaseModel, ConfigDict, Field


class AttackScenarioResponse(BaseModel):
    """Scenario details response schema."""

    scenario_id: str
    name: str
    description: str
    category: str
    severity: str
    attack_type: str
    input_payload: str
    expected_behavior: str
    expected_decision: str
    enabled: bool
    created_at: datetime

    model_config = ConfigDict(populate_by_name=True)


class ScenarioListResponse(BaseModel):
    """List of available attack scenarios."""

    scenarios: list[AttackScenarioResponse]
    total: int


class SimulationRunRequest(BaseModel):
    """Payload to trigger an attack simulation run."""

    scenario_ids: Optional[list[str]] = Field(default=None, description="Specific scenario IDs to execute")
    category: Optional[str] = Field(default=None, description="Filter scenario category to run")


class ScenarioExecutionResultResponse(BaseModel):
    """Outcome schema for a single attack scenario execution."""

    scenario_id: str
    scenario_name: str
    category: str
    severity: str
    attack_type: str
    input_payload_summary: str
    expected_behavior: str
    actual_decision: str
    verdict: str  # blocked | detected_not_blocked | attack_succeeded | inconclusive | error
    verdict_reason: str
    security_event_id: Optional[str] = None
    duration_ms: float
    signals_detected: list[dict[str, Any]] = Field(default_factory=list)
    execution_timestamp: datetime
    error_details: Optional[str] = None

    model_config = ConfigDict(populate_by_name=True)


class SimulationRunSummaryResponse(BaseModel):
    """Aggregated outcome metrics for a run."""

    total_executed: int
    blocked: int
    detected_not_blocked: int
    attack_succeeded: int
    inconclusive: int
    error: int
    block_rate_percent: float


class SimulationRunResponse(BaseModel):
    """Complete simulation run result schema."""

    id: str
    owner_id: str
    status: str
    scenarios_count: int
    results: list[ScenarioExecutionResultResponse] = Field(default_factory=list)
    summary: SimulationRunSummaryResponse
    duration_ms: float
    created_at: datetime

    model_config = ConfigDict(populate_by_name=True)


class SimulationHistoryResponse(BaseModel):
    """Paginated list of user's past simulation runs."""

    runs: list[SimulationRunResponse]
    total: int


class SimulationStatsResponse(BaseModel):
    """Cumulative simulation metrics for the authenticated user."""

    total_runs: int
    total_executed: int
    blocked: int
    detected_not_blocked: int
    attack_succeeded: int
    inconclusive: int
    error: int
    block_rate_percent: float

