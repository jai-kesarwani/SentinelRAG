"""
SentinelRAG — Central RAG Security Gateway.

Coordinates multi-stage defense-in-depth across the entire RAG pipeline:
  Stage 1: Pre-retrieval query screening & prompt injection detection.
  Stage 2: Semantic retrieval authorization and cross-tenant context guarding.
  Stage 3: Pre-LLM gate enforcement (fail-closed before LLM invocation).
  Stage 4: Isolated untrusted context formatting.
  Stage 5: Post-generation output inspection, canary tracking, and sanitization.

All security blocks, leakages, and sanitizations are auditable via MongoDB security_events.
"""
from __future__ import annotations

from typing import Any, Optional

from app.core.logging import get_logger
from app.db.security_events_repo import security_events_repo
from app.services.canary_service import canary_service
from app.services.output_security_service import (
    OutputSecurityResult,
    output_security_service,
)
from app.services.query_security_service import (
    QuerySecurityResult,
    query_security_service,
)
from app.services.retrieval_service import RetrievedChunk
from app.services.security_policy_engine import (
    PolicyDecision,
    ReasonCode,
)

logger = get_logger(__name__)

GATEWAY_VERSION = "1.0.0"


class PreLLMGateResult:
    """Decision from the Pre-LLM security gate."""

    def __init__(self, is_allowed: bool, reason_code: str, refusal_message: Optional[str] = None):
        self.is_allowed = is_allowed
        self.reason_code = reason_code
        self.refusal_message = refusal_message


class RAGSecurityGateway:
    """Central gateway enforcing security boundaries around retrieval and generation."""

    def __init__(self):
        self.query_scanner = query_security_service
        self.output_scanner = output_security_service
        self.canary = canary_service

    async def inspect_query(
        self,
        query: str,
        owner_id: str,
        correlation_id: Optional[str] = None,
    ) -> QuerySecurityResult:
        """
        Stage 1: Inspect user query before retrieval.
        Logs security event if blocked.
        """
        result = self.query_scanner.inspect_query(query)

        if not result.is_allowed:
            logger.warning(
                "Query blocked by Security Gateway",
                extra={
                    "owner_id": owner_id,
                    "reason_code": result.reason_code.value,
                    "severity": result.severity,
                    "correlation_id": correlation_id,
                },
            )
            # Record auditable security event in MongoDB
            primary_cat = result.signals[0].category if result.signals else "unknown"
            await security_events_repo.record_event(
                event_type="query_injection_blocked",
                severity=result.severity,
                decision="block",
                reason_code=result.reason_code.value,
                resource_type="query",
                owner_id=owner_id,
                actor_user_id=owner_id,
                correlation_id=correlation_id,
                detector_name="sentinel_query_guard",
                detector_version=GATEWAY_VERSION,
                safe_metadata={
                    "category": primary_cat,
                    "signals_count": result.signals_count,
                    "explanation": result.explanation,
                },
            )

        return result

    async def validate_retrieval_context(
        self,
        chunks: list[RetrievedChunk],
        owner_id: str,
        correlation_id: Optional[str] = None,
    ) -> list[RetrievedChunk]:
        """
        Stage 2: Context Guard — double-checks tenant isolation on retrieved chunks.
        """
        validated_chunks: list[RetrievedChunk] = []

        for chunk in chunks:
            if chunk.owner_id != owner_id:
                logger.critical(
                    "SECURITY BREACH ATTEMPT: Retrieved chunk does not match session owner",
                    extra={
                        "chunk_id": chunk.chunk_id,
                        "chunk_owner": chunk.owner_id,
                        "session_owner": owner_id,
                        "correlation_id": correlation_id,
                    },
                )
                await security_events_repo.record_event(
                    event_type="cross_tenant_chunk_blocked",
                    severity="critical",
                    decision="block",
                    reason_code=ReasonCode.UNAUTHORIZED_RETRIEVAL_CONTEXT.value,
                    resource_type="document_chunk",
                    resource_id=chunk.chunk_id,
                    owner_id=owner_id,
                    actor_user_id=owner_id,
                    correlation_id=correlation_id,
                    detector_name="sentinel_context_guard",
                    detector_version=GATEWAY_VERSION,
                    safe_metadata={"action": "dropped_unauthorized_chunk"},
                )
                continue

            validated_chunks.append(chunk)

        return validated_chunks

    async def evaluate_pre_llm_gate(
        self,
        query_result: QuerySecurityResult,
        owner_id: str,
        correlation_id: Optional[str] = None,
    ) -> PreLLMGateResult:
        """
        Stage 3: Pre-LLM Fail-Closed Gate.
        Aborts execution if query inspection failed or context is compromised.
        """
        if not query_result.is_allowed:
            await security_events_repo.record_event(
                event_type="pre_llm_blocked",
                severity=query_result.severity,
                decision="block",
                reason_code=query_result.reason_code.value,
                resource_type="query",
                owner_id=owner_id,
                actor_user_id=owner_id,
                correlation_id=correlation_id,
                detector_name="sentinel_pre_llm_gate",
                detector_version=GATEWAY_VERSION,
                safe_metadata={"action": "llm_call_prevented"},
            )
            return PreLLMGateResult(
                is_allowed=False,
                reason_code=query_result.reason_code.value,
                refusal_message=query_result.refusal_message,
            )

        return PreLLMGateResult(
            is_allowed=True,
            reason_code=ReasonCode.NORMAL.value,
        )

    async def inspect_and_sanitize_output(
        self,
        raw_output: str,
        authorized_chunks: list[RetrievedChunk],
        owner_id: str,
        conversation_id: str,
        correlation_id: Optional[str] = None,
        active_canary: Optional[str] = None,
    ) -> OutputSecurityResult:
        """
        Stage 5: Post-Generation Output Inspection & Sanitization.
        Detects canary leakage, credentials, unsafe schemas, and logs events.
        """
        result = self.output_scanner.inspect_and_sanitize(
            output_text=raw_output,
            authorized_chunks=authorized_chunks,
            active_canary=active_canary,
        )

        if result.canary_leaked:
            logger.critical(
                "Output blocked due to Canary leakage",
                extra={
                    "owner_id": owner_id,
                    "conversation_id": conversation_id,
                    "correlation_id": correlation_id,
                },
            )
            await security_events_repo.record_event(
                event_type="output_canary_leakage_detected",
                severity="critical",
                decision="block",
                reason_code=result.reason_code.value,
                resource_type="conversation",
                resource_id=conversation_id,
                owner_id=owner_id,
                actor_user_id=owner_id,
                correlation_id=correlation_id,
                detector_name="sentinel_output_guard",
                detector_version=GATEWAY_VERSION,
                safe_metadata={"signals": result.signals},
            )
        elif result.credential_leaked or result.unsafe_schema_detected:
            logger.warning(
                "Output sanitized by Security Gateway",
                extra={
                    "owner_id": owner_id,
                    "conversation_id": conversation_id,
                    "reason_code": result.reason_code.value,
                },
            )
            await security_events_repo.record_event(
                event_type="output_sanitized",
                severity=result.severity,
                decision="sanitize",
                reason_code=result.reason_code.value,
                resource_type="conversation",
                resource_id=conversation_id,
                owner_id=owner_id,
                actor_user_id=owner_id,
                correlation_id=correlation_id,
                detector_name="sentinel_output_guard",
                detector_version=GATEWAY_VERSION,
                safe_metadata={"signals": result.signals},
            )

        return result


security_gateway = RAGSecurityGateway()

