"""
SentinelRAG — Attack Simulator Execution Engine.

Executes controlled, isolated adversarial scenarios against the actual SentinelRAG
security gateway (Stages 1–5) using synthetic test fixtures without accessing real
user documents or invoking external LLM APIs.
"""
from __future__ import annotations

import time
import uuid
from datetime import datetime, timezone
from typing import Any, Optional

from app.core.logging import get_logger
from app.db.simulation_repo import simulation_repo
from app.models.attack_scenario import AttackScenario, AttackType
from app.models.simulation import (
    ScenarioExecutionResult,
    SimulationRunInDB,
    SimulationRunSummary,
    SimulationVerdict,
)
from app.services.attack_scenarios import scenario_catalog
from app.services.output_security_service import output_security_service
from app.services.query_security_service import query_security_service
from app.services.retrieval_service import RetrievedChunk
from app.services.security_gateway import security_gateway
from app.services.security_scanner import DocumentSecurityScanner

logger = get_logger(__name__)

# Dedicated synthetic document scanner instance for isolated test context
_isolated_doc_scanner = DocumentSecurityScanner()


class SimulationExecutionService:
    """Orchestrates controlled adversarial attack simulation runs."""

    async def execute_scenario(
        self,
        scenario: AttackScenario,
        owner_id: str,
        correlation_id: Optional[str] = None,
    ) -> ScenarioExecutionResult:
        """
        Execute an individual attack scenario against the appropriate security layer.

        Args:
            scenario: The attack scenario definition.
            owner_id: Authenticated session user ID.
            correlation_id: Request correlation ID.

        Returns:
            ScenarioExecutionResult with actual gateway decision, verdict, and evidence.
        """
        start_time = time.perf_counter()
        sim_corr_id = correlation_id or f"sim_{uuid.uuid4().hex[:12]}"
        payload_summary = (
            (scenario.input_payload[:120] + "...")
            if len(scenario.input_payload) > 120
            else scenario.input_payload
        )

        try:
            # -----------------------------------------------------------------
            # 1. Query Inspection (Gateway Stage 1 / Query Guard)
            # -----------------------------------------------------------------
            if scenario.attack_type == AttackType.QUERY_INSPECTION:
                query_res = await security_gateway.inspect_query(
                    query=scenario.input_payload,
                    owner_id=owner_id,
                    correlation_id=sim_corr_id,
                )
                duration_ms = (time.perf_counter() - start_time) * 1000.0

                if not query_res.is_allowed:
                    verdict = SimulationVerdict.BLOCKED
                    reason = (
                        f"Query Guard detected threat pattern ({query_res.reason_code.value}) "
                        f"and enforced fail-closed block."
                    )
                elif query_res.signals_count > 0:
                    verdict = SimulationVerdict.DETECTED_NOT_BLOCKED
                    reason = "Threat signals were identified, but policy decision permitted execution."
                else:
                    verdict = SimulationVerdict.ATTACK_SUCCEEDED
                    reason = "Query bypassed pre-retrieval inspection without triggering detection rules."

                return ScenarioExecutionResult(
                    scenario_id=scenario.scenario_id,
                    scenario_name=scenario.name,
                    category=scenario.category.value,
                    severity=scenario.severity.value,
                    attack_type=scenario.attack_type.value,
                    input_payload_summary=payload_summary,
                    expected_behavior=scenario.expected_behavior,
                    actual_decision=query_res.policy_decision.value,
                    verdict=verdict,
                    verdict_reason=reason,
                    duration_ms=duration_ms,
                    signals_detected=[s.model_dump() for s in query_res.signals],
                )

            # -----------------------------------------------------------------
            # 2. Document Inspection (Gateway Ingestion / Document Scanner)
            # -----------------------------------------------------------------
            elif scenario.attack_type == AttackType.DOCUMENT_INSPECTION:
                # Run against isolated document security scanner in synthetic namespace
                scan_res = _isolated_doc_scanner.scan_document(
                    document_id="synthetic-sim-doc",
                    owner_id=owner_id,
                    filename="synthetic-document.pdf",
                    pages=[{"page_number": 1, "text": scenario.input_payload}],
                )
                duration_ms = (time.perf_counter() - start_time) * 1000.0

                if scan_res.policy_decision in ["quarantined", "review"]:
                    verdict = SimulationVerdict.BLOCKED
                    reason = (
                        f"Document Security Scanner flagged malicious embedded content "
                        f"({scan_res.reason_code}) and assigned policy decision: {scan_res.policy_decision}."
                    )
                elif scan_res.signals_count > 0:
                    verdict = SimulationVerdict.DETECTED_NOT_BLOCKED
                    reason = "Document signals were detected, but document was not quarantined."
                else:
                    verdict = SimulationVerdict.ATTACK_SUCCEEDED
                    reason = "Embedded instructions passed document scanner without detection."

                return ScenarioExecutionResult(
                    scenario_id=scenario.scenario_id,
                    scenario_name=scenario.name,
                    category=scenario.category.value,
                    severity=scenario.severity.value,
                    attack_type=scenario.attack_type.value,
                    input_payload_summary=payload_summary,
                    expected_behavior=scenario.expected_behavior,
                    actual_decision=scan_res.policy_decision,
                    verdict=verdict,
                    verdict_reason=reason,
                    duration_ms=duration_ms,
                    signals_detected=[s.model_dump() for s in scan_res.signals],
                )

            # -----------------------------------------------------------------
            # 3. Retrieval Guard (Gateway Stage 2 / Cross-Tenant Context Guard)
            # -----------------------------------------------------------------
            elif scenario.attack_type == AttackType.RETRIEVAL_GUARD:
                # Synthesize a cross-tenant chunk belonging to an unauthorized third-party
                rogue_chunk = RetrievedChunk(
                    chunk_id="synthetic-rogue-chunk-403",
                    document_id="synthetic-rogue-doc-403",
                    owner_id="synthetic_unauthorized_tenant_999",
                    page_number=1,
                    chunk_index=0,
                    source_filename="restricted_records.pdf",
                    text="Confidential external tenant data.",
                )
                validated_chunks = await security_gateway.validate_retrieval_context(
                    chunks=[rogue_chunk],
                    owner_id=owner_id,
                    correlation_id=sim_corr_id,
                )
                duration_ms = (time.perf_counter() - start_time) * 1000.0

                if len(validated_chunks) == 0:
                    verdict = SimulationVerdict.BLOCKED
                    reason = "Retrieval Context Guard identified tenant ID mismatch and dropped unauthorized chunk."
                    decision = "block"
                else:
                    verdict = SimulationVerdict.ATTACK_SUCCEEDED
                    reason = "Cross-tenant chunk was not dropped by Context Guard."
                    decision = "allow"

                return ScenarioExecutionResult(
                    scenario_id=scenario.scenario_id,
                    scenario_name=scenario.name,
                    category=scenario.category.value,
                    severity=scenario.severity.value,
                    attack_type=scenario.attack_type.value,
                    input_payload_summary=payload_summary,
                    expected_behavior=scenario.expected_behavior,
                    actual_decision=decision,
                    verdict=verdict,
                    verdict_reason=reason,
                    duration_ms=duration_ms,
                    signals_detected=[{"type": "cross_tenant_check", "dropped": len(validated_chunks) == 0}],
                )

            # -----------------------------------------------------------------
            # 4. Output Inspection (Gateway Stage 5 / Output Guard)
            # -----------------------------------------------------------------
            elif scenario.attack_type == AttackType.OUTPUT_INSPECTION:
                output_to_test = scenario.mock_output or scenario.input_payload
                out_res = output_security_service.inspect_and_sanitize(output_text=output_to_test)
                duration_ms = (time.perf_counter() - start_time) * 1000.0

                if out_res.canary_leaked:
                    if out_res.is_blocked:
                        verdict = SimulationVerdict.BLOCKED
                        reason = "Output Guard detected internal canary disclosure and completely blocked response."
                    else:
                        verdict = SimulationVerdict.DETECTED_NOT_BLOCKED
                        reason = "Canary leakage detected, but response was not blocked."
                elif out_res.credential_leaked or out_res.unsafe_schema_detected:
                    if scenario.expected_decision == "sanitize" or out_res.policy_decision.value == "sanitize":
                        verdict = SimulationVerdict.BLOCKED
                        reason = (
                            f"Output Guard neutralized sensitive data/script ({out_res.reason_code.value}) "
                            f"via active content sanitization."
                        )
                    else:
                        verdict = SimulationVerdict.DETECTED_NOT_BLOCKED
                        reason = "Content sanitized, but full block was expected."
                else:
                    verdict = SimulationVerdict.ATTACK_SUCCEEDED
                    reason = "Potentially hazardous output content passed Output Guard unmodified."

                return ScenarioExecutionResult(
                    scenario_id=scenario.scenario_id,
                    scenario_name=scenario.name,
                    category=scenario.category.value,
                    severity=scenario.severity.value,
                    attack_type=scenario.attack_type.value,
                    input_payload_summary=payload_summary,
                    expected_behavior=scenario.expected_behavior,
                    actual_decision=out_res.policy_decision.value,
                    verdict=verdict,
                    verdict_reason=reason,
                    duration_ms=duration_ms,
                    signals_detected=out_res.signals,
                )

            # -----------------------------------------------------------------
            # Fallback for undefined attack types
            # -----------------------------------------------------------------
            else:
                duration_ms = (time.perf_counter() - start_time) * 1000.0
                return ScenarioExecutionResult(
                    scenario_id=scenario.scenario_id,
                    scenario_name=scenario.name,
                    category=scenario.category.value,
                    severity=scenario.severity.value,
                    attack_type=scenario.attack_type.value,
                    input_payload_summary=payload_summary,
                    expected_behavior=scenario.expected_behavior,
                    actual_decision="inconclusive",
                    verdict=SimulationVerdict.INCONCLUSIVE,
                    verdict_reason=f"No execution handler configured for attack type: {scenario.attack_type.value}",
                    duration_ms=duration_ms,
                )

        except Exception as exc:  # noqa: BLE001
            duration_ms = (time.perf_counter() - start_time) * 1000.0
            logger.error(
                "Error executing attack simulation scenario",
                extra={"scenario_id": scenario.scenario_id, "error": str(exc)},
            )
            # NEVER report errors as blocked (Section 3.D & 7)
            return ScenarioExecutionResult(
                scenario_id=scenario.scenario_id,
                scenario_name=scenario.name,
                category=scenario.category.value,
                severity=scenario.severity.value,
                attack_type=scenario.attack_type.value,
                input_payload_summary=payload_summary,
                expected_behavior=scenario.expected_behavior,
                actual_decision="error",
                verdict=SimulationVerdict.ERROR,
                verdict_reason="Execution threw an unhandled exception in security gateway component.",
                duration_ms=duration_ms,
                error_details=str(exc),
            )

    async def run_simulation(
        self,
        owner_id: str,
        scenario_ids: Optional[list[str]] = None,
        category: Optional[str] = None,
        correlation_id: Optional[str] = None,
    ) -> SimulationRunInDB:
        """
        Execute a batch of attack scenarios for an authenticated user and persist the run.

        Args:
            owner_id: Authenticated user ID.
            scenario_ids: Optional list of specific scenario IDs to run.
            category: Optional category filter.
            correlation_id: Tracking correlation ID.

        Returns:
            Completed SimulationRunInDB record.
        """
        overall_start = time.perf_counter()

        # Step 1: Resolve scenarios to run
        if scenario_ids:
            scenarios: list[AttackScenario] = []
            for s_id in scenario_ids:
                scen = scenario_catalog.get_scenario(s_id)
                if scen and scen.enabled:
                    scenarios.append(scen)
        else:
            scenarios = scenario_catalog.list_scenarios(category=category)

        if not scenarios:
            raise ValueError("No valid or enabled attack scenarios selected for execution.")

        # Step 2: Execute each scenario sequentially in isolated context
        results: list[ScenarioExecutionResult] = []
        for scenario in scenarios:
            res = await self.execute_scenario(
                scenario=scenario,
                owner_id=owner_id,
                correlation_id=correlation_id,
            )
            results.append(res)

        # Step 3: Compute aggregated metrics
        total = len(results)
        blocked_count = sum(1 for r in results if r.verdict == SimulationVerdict.BLOCKED)
        det_not_blocked = sum(1 for r in results if r.verdict == SimulationVerdict.DETECTED_NOT_BLOCKED)
        attack_succ = sum(1 for r in results if r.verdict == SimulationVerdict.ATTACK_SUCCEEDED)
        inconc_count = sum(1 for r in results if r.verdict == SimulationVerdict.INCONCLUSIVE)
        error_count = sum(1 for r in results if r.verdict == SimulationVerdict.ERROR)
        block_rate = round((blocked_count / total * 100), 1) if total > 0 else 0.0
        total_duration_ms = (time.perf_counter() - overall_start) * 1000.0

        summary = SimulationRunSummary(
            total_executed=total,
            blocked=blocked_count,
            detected_not_blocked=det_not_blocked,
            attack_succeeded=attack_succ,
            inconclusive=inconc_count,
            error=error_count,
            block_rate_percent=block_rate,
        )

        run_id = f"simrun_{uuid.uuid4().hex[:16]}"
        run_record = SimulationRunInDB(
            _id=run_id,
            owner_id=owner_id,
            status="completed",
            scenarios_count=total,
            results=results,
            summary=summary,
            duration_ms=total_duration_ms,
            created_at=datetime.now(timezone.utc),
        )

        # Step 4: Persist in MongoDB
        await simulation_repo.create_run(run_record)

        return run_record


simulation_service = SimulationExecutionService()
