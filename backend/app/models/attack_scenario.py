"""
SentinelRAG — Attack Scenario Domain Models.

Defines schemas and enums for predefined adversarial scenarios in the Attack Simulator Lab.
"""
from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Optional

from pydantic import BaseModel, Field


class AttackCategory(str, Enum):
    """Core categories of prompt injection and RAG security attacks."""
    DIRECT_PROMPT_INJECTION = "direct_prompt_injection"
    SYSTEM_PROMPT_EXTRACTION = "system_prompt_extraction"
    INDIRECT_PROMPT_INJECTION = "indirect_prompt_injection"
    DATA_EXFILTRATION = "data_exfiltration"
    CROSS_TENANT_ACCESS = "cross_tenant_access"
    OBFUSCATED_INJECTION = "obfuscated_injection"
    CREDENTIAL_CANARY_LEAKAGE = "credential_canary_leakage"
    MALICIOUS_OUTPUT = "malicious_output"


class AttackType(str, Enum):
    """The security pipeline stage targeted by the scenario."""
    QUERY_INSPECTION = "query_inspection"
    DOCUMENT_INSPECTION = "document_inspection"
    RETRIEVAL_GUARD = "retrieval_guard"
    OUTPUT_INSPECTION = "output_inspection"
    END_TO_END_RAG = "end_to_end_rag"


class AttackSeverity(str, Enum):
    """Severity classification for the attack scenario."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class AttackScenario(BaseModel):
    """Definition of an individual attack test case."""

    scenario_id: str
    name: str
    description: str
    category: AttackCategory
    severity: AttackSeverity
    attack_type: AttackType
    input_payload: str
    mock_output: Optional[str] = None
    expected_behavior: str
    expected_decision: str = "block"  # block | sanitize | quarantined
    enabled: bool = True
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    def to_public_dict(self) -> dict[str, Any]:
        """Convert to public dictionary representation."""
        return {
            "scenario_id": self.scenario_id,
            "name": self.name,
            "description": self.description,
            "category": self.category.value,
            "severity": self.severity.value,
            "attack_type": self.attack_type.value,
            "input_payload": self.input_payload,
            "expected_behavior": self.expected_behavior,
            "expected_decision": self.expected_decision,
            "enabled": self.enabled,
            "created_at": self.created_at,
        }

