"""
SentinelRAG — Security Event Domain Model.

Matches MongoDB 'security_events' collection defined in
docs/04_SECURITY_SPECIFICATION.md and docs/05_DATABASE_SPECIFICATION.md.
"""
from __future__ import annotations

from datetime import datetime
from typing import Any, Optional

from pydantic import BaseModel, Field


class DetectorInfo(BaseModel):
    """Information identifying the scanning engine or classifier."""

    name: str = "sentinel_deterministic_scanner"
    version: str = "1.0.0"


class SecurityEventInDB(BaseModel):
    """MongoDB record for an auditable security event."""

    id: str = Field(alias="_id")
    owner_id: Optional[str] = None
    actor_user_id: Optional[str] = None
    correlation_id: Optional[str] = None
    event_type: str  # document_injection_detected | document_scan_completed | document_quarantined | document_approved | document_rescanned
    severity: str = "low"  # low | medium | high | critical
    resource_type: str = "document"  # document | conversation | query
    resource_id: Optional[str] = None
    decision: str = "allow"  # allow | review | quarantined
    reason_code: str = "NORMAL"  # NORMAL | INJECTION_RISK | EXFILTRATION_RISK | SYSTEM_OVERRIDE | MANUAL_OVERRIDE
    detector: DetectorInfo = Field(default_factory=DetectorInfo)
    safe_metadata: dict[str, Any] = Field(default_factory=dict)
    created_at: datetime

    def to_public_dict(self) -> dict[str, Any]:
        """Convert to public dictionary representation."""
        return {
            "id": self.id,
            "owner_id": self.owner_id,
            "actor_user_id": self.actor_user_id,
            "correlation_id": self.correlation_id,
            "event_type": self.event_type,
            "severity": self.severity,
            "resource_type": self.resource_type,
            "resource_id": self.resource_id,
            "decision": self.decision,
            "reason_code": self.reason_code,
            "detector": self.detector.model_dump(),
            "safe_metadata": self.safe_metadata,
            "created_at": self.created_at,
        }

