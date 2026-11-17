"""
SentinelRAG — Attack Simulation Domain Models.

Defines schemas for simulation execution runs, test verdicts, and persistent records
stored in the MongoDB 'attack_simulation_runs' collection.
"""
from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Optional

from pydantic import BaseModel, Field


class SimulationVerdict(str, Enum):
    """
    Standardized attack evaluation verdicts required by SentinelRAG:
      - blocked: The attack was prevented by the relevant security enforcement layer.
      - detected_not_blocked: The attack was detected, but enforcement did not prevent the unsafe behavior.
      - attack_succeeded: The attack achieved its defined unsafe objective in the controlled test.
      - inconclusive: Available evidence is insufficient to determine the outcome.
      - error: The simulation could not execute correctly.
    """
    BLOCKED = "blocked"
    DETECTED_NOT_BLOCKED = "detected_not_blocked"
    ATTACK_SUCCEEDED = "attack_succeeded"
    INCONCLUSIVE = "inconclusive"
    ERROR = "error"


class ScenarioExecutionResult(BaseModel):
    """Detailed result of executing a single attack scenario against the security gateway."""

    scenario_id: str
    scenario_name: str
    category: str
    severity: str
    attack_type: str
    input_payload_summary: str
    expected_behavior: str
    actual_decision: str  # block | allow | sanitize | review | quarantined | error
    verdict: SimulationVerdict
    verdict_reason: str
    security_event_id: Optional[str] = None
    duration_ms: float = 0.0
    signals_detected: list[dict[str, Any]] = Field(default_factory=list)
    execution_timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    error_details: Optional[str] = None

    def to_public_dict(self) -> dict[str, Any]:
        """Convert to public dictionary representation."""
        return {
            "scenario_id": self.scenario_id,
            "scenario_name": self.scenario_name,
            "category": self.category,
            "severity": self.severity,
            "attack_type": self.attack_type,
            "input_payload_summary": self.input_payload_summary,
            "expected_behavior": self.expected_behavior,
            "actual_decision": self.actual_decision,
            "verdict": self.verdict.value,
            "verdict_reason": self.verdict_reason,
            "security_event_id": self.security_event_id,
            "duration_ms": round(self.duration_ms, 2),
            "signals_detected": self.signals_detected,
            "execution_timestamp": self.execution_timestamp,
            "error_details": self.error_details,
        }


class SimulationRunSummary(BaseModel):
    """Aggregated outcome metrics for a simulation run."""

    total_executed: int = 0
    blocked: int = 0
    detected_not_blocked: int = 0
    attack_succeeded: int = 0
    inconclusive: int = 0
    error: int = 0
    block_rate_percent: float = 0.0


class SimulationRunInDB(BaseModel):
    """MongoDB record for a completed attack simulation run."""

    id: str = Field(alias="_id")
    owner_id: str
    status: str = "completed"  # completed | failed | running
    scenarios_count: int
    results: list[ScenarioExecutionResult] = Field(default_factory=list)
    summary: SimulationRunSummary = Field(default_factory=SimulationRunSummary)
    duration_ms: float = 0.0
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    def to_public_dict(self) -> dict[str, Any]:
        """Convert to public dictionary representation."""
        return {
            "id": self.id,
            "owner_id": self.owner_id,
            "status": self.status,
            "scenarios_count": self.scenarios_count,
            "results": [r.to_public_dict() for r in self.results],
            "summary": self.summary.model_dump(),
            "duration_ms": round(self.duration_ms, 2),
            "created_at": self.created_at,
        }

