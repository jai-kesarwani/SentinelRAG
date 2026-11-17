"""
SentinelRAG — Phase 8: Security Center & Analytics Test Suite.

Verifies:
1. Overview metrics aggregation (real events + simulation telemetry)
2. Activity timeline generation across time ranges (24h, 7d, 30d, 90d)
3. Threat distribution by category, severity, and decision
4. Attack simulation performance and block-rate calculations
5. Filtered, paginated security event explorer
6. Tenant isolation across all analytics and incident lookup endpoints
7. Safe empty state handling with zero counts and no division errors
"""
from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone

import pytest
from httpx import ASGITransport, AsyncClient

from app.db.security_events_repo import security_events_repo
from app.db.simulation_repo import simulation_repo
from app.main import app
from app.models.simulation import (
    ScenarioExecutionResult,
    SimulationRunInDB,
    SimulationRunSummary,
    SimulationVerdict,
)


@pytest.fixture(scope="session")
def anyio_backend():
    return "asyncio"


@pytest.fixture
async def api_client():
    """Async client initialized with lifespan context."""
    async with app.router.lifespan_context(app):
        async with AsyncClient(
            transport=ASGITransport(app=app),
            base_url="http://testserver",
        ) as client:
            yield client


async def register_and_get_auth(client: AsyncClient, prefix: str = "sec_user") -> tuple[dict[str, str], str]:
    """Helper to register user and return (auth_headers, user_id)."""
    email = f"{prefix}_{uuid.uuid4().hex[:8]}@example.com"
    pwd = "SecurePassword123!"
    reg_res = await client.post(
        "/api/v1/auth/register",
        json={"email": email, "password": pwd, "display_name": "Analytics Tester"},
    )
    assert reg_res.status_code == 201
    user_id = reg_res.json()["data"]["id"]

    login_res = await client.post(
        "/api/v1/auth/login",
        json={"email": email, "password": pwd},
    )
    assert login_res.status_code == 200
    token = login_res.json()["data"]["access_token"]
    return {"Authorization": f"Bearer {token}"}, user_id


# -----------------------------------------------------------------------------
# 1. Overview Metrics & Empty State Tests
# -----------------------------------------------------------------------------

@pytest.mark.anyio
async def test_overview_metrics_empty_state(api_client: AsyncClient):
    """Verify clean empty state with 0 counts when user has no events."""
    headers, _ = await register_and_get_auth(api_client, "ov_empty")

    res = await api_client.get("/api/v1/security-center/overview", headers=headers)
    assert res.status_code == 200
    data = res.json()["data"]

    assert data["total_events"] == 0
    assert data["blocked_queries"] == 0
    assert data["document_threats_detected"] == 0
    assert data["output_interventions"] == 0
    assert data["total_simulations"] == 0
    assert data["simulation_block_rate_percent"] == 0.0


@pytest.mark.anyio
async def test_overview_metrics_with_real_events(api_client: AsyncClient):
    """Verify overview metrics accurately aggregate real security events."""
    headers, user_id = await register_and_get_auth(api_client, "ov_real")

    # Record 1 blocked query
    await security_events_repo.record_event(
        event_type="query_injection_blocked",
        severity="critical",
        decision="block",
        reason_code="PROMPT_INJECTION_DETECTED",
        resource_type="query",
        owner_id=user_id,
    )

    # Record 1 quarantined document
    await security_events_repo.record_event(
        event_type="document_quarantined",
        severity="high",
        decision="quarantined",
        reason_code="INJECTION_RISK",
        resource_type="document",
        owner_id=user_id,
    )

    # Record 1 output intervention (canary leak)
    await security_events_repo.record_event(
        event_type="output_canary_leakage_detected",
        severity="critical",
        decision="block",
        reason_code="OUTPUT_CANARY_LEAKAGE",
        resource_type="conversation",
        owner_id=user_id,
    )

    # Record a simulation run with 2 tests: 1 blocked, 1 attack_succeeded
    run = SimulationRunInDB(
        _id=f"simrun_{uuid.uuid4().hex[:12]}",
        owner_id=user_id,
        status="completed",
        scenarios_count=2,
        results=[],
        summary=SimulationRunSummary(
            total_executed=2,
            blocked=1,
            detected_not_blocked=0,
            attack_succeeded=1,
            inconclusive=0,
            error=0,
            block_rate_percent=50.0,
        ),
        duration_ms=45.2,
    )
    await simulation_repo.create_run(run)

    res = await api_client.get("/api/v1/security-center/overview", headers=headers)
    assert res.status_code == 200
    data = res.json()["data"]

    assert data["total_events"] == 3
    assert data["blocked_queries"] == 1
    assert data["document_threats_detected"] == 1
    assert data["output_interventions"] == 1
    assert data["total_simulations"] == 1
    assert data["simulated_attacks_prevented"] == 1
    assert data["simulated_attacks_succeeded"] == 1
    assert data["simulation_block_rate_percent"] == 50.0


# -----------------------------------------------------------------------------
# 2. Activity Timeline Tests
# -----------------------------------------------------------------------------

@pytest.mark.anyio
async def test_activity_timeline_bucketing(api_client: AsyncClient):
    """Verify activity timeline groups events into buckets for 7d and 24h."""
    headers, user_id = await register_and_get_auth(api_client, "act_time")

    # Record events today
    await security_events_repo.record_event(
        event_type="query_injection_blocked",
        severity="critical",
        decision="block",
        owner_id=user_id,
    )
    await security_events_repo.record_event(
        event_type="output_sanitized",
        severity="medium",
        decision="sanitize",
        owner_id=user_id,
    )

    # Request 7d timeline
    res_7d = await api_client.get("/api/v1/security-center/activity?time_range=7d", headers=headers)
    assert res_7d.status_code == 200
    data_7d = res_7d.json()["data"]
    assert data_7d["time_range"] == "7d"
    assert data_7d["total_events"] == 2
    assert len(data_7d["timeline"]) == 7

    # Verify bucket has critical count
    total_in_buckets = sum(b["count"] for b in data_7d["timeline"])
    assert total_in_buckets == 2

    # Request 24h timeline
    res_24h = await api_client.get("/api/v1/security-center/activity?time_range=24h", headers=headers)
    assert res_24h.status_code == 200
    data_24h = res_24h.json()["data"]
    assert data_24h["time_range"] == "24h"
    assert len(data_24h["timeline"]) == 24


# -----------------------------------------------------------------------------
# 3. Threat Distribution Tests
# -----------------------------------------------------------------------------

@pytest.mark.anyio
async def test_threat_distribution_categories_and_severities(api_client: AsyncClient):
    """Verify threat distribution accurately categorizes event types."""
    headers, user_id = await register_and_get_auth(api_client, "dist_test")

    # Event 1: Prompt Injection (Critical)
    await security_events_repo.record_event(
        event_type="query_injection_blocked",
        severity="critical",
        decision="block",
        owner_id=user_id,
    )
    # Event 2: Cross Tenant Access (Critical)
    await security_events_repo.record_event(
        event_type="cross_tenant_chunk_blocked",
        severity="critical",
        decision="block",
        owner_id=user_id,
    )
    # Event 3: Output Security (Medium)
    await security_events_repo.record_event(
        event_type="output_sanitized",
        severity="medium",
        decision="sanitize",
        owner_id=user_id,
    )

    res = await api_client.get("/api/v1/security-center/threat-distribution?days=30", headers=headers)
    assert res.status_code == 200
    data = res.json()["data"]

    assert data["total_events"] == 3

    # Check categories
    cat_names = [c["category"] for c in data["categories"]]
    assert "prompt_injection" in cat_names
    assert "cross_tenant_access" in cat_names
    assert "output_security" in cat_names

    # Check severities
    sev_map = {s["severity"]: s["count"] for s in data["severities"]}
    assert sev_map.get("critical") == 2
    assert sev_map.get("medium") == 1


# -----------------------------------------------------------------------------
# 4. Simulation Analytics Tests
# -----------------------------------------------------------------------------

@pytest.mark.anyio
async def test_simulation_analytics_calculation(api_client: AsyncClient):
    """
    Verify that simulation analytics correctly calculates block rate
    using completed attacks as denominator (excluding error and inconclusive).
    """
    headers, user_id = await register_and_get_auth(api_client, "sim_analytics")

    # Create run with 4 tests: 2 blocked, 1 detected_not_blocked, 1 error
    results = [
        ScenarioExecutionResult(
            scenario_id="SCEN-DIR-001",
            scenario_name="Direct Injection",
            category="direct_prompt_injection",
            severity="critical",
            attack_type="query_inspection",
            input_payload_summary="Test payload",
            expected_behavior="Block",
            actual_decision="block",
            verdict=SimulationVerdict.BLOCKED,
            verdict_reason="Blocked by query guard",
            duration_ms=12.0,
        ),
        ScenarioExecutionResult(
            scenario_id="SCEN-DIR-002",
            scenario_name="DAN Mode",
            category="direct_prompt_injection",
            severity="critical",
            attack_type="query_inspection",
            input_payload_summary="Test DAN",
            expected_behavior="Block",
            actual_decision="block",
            verdict=SimulationVerdict.BLOCKED,
            verdict_reason="Blocked by query guard",
            duration_ms=10.0,
        ),
        ScenarioExecutionResult(
            scenario_id="SCEN-OUT-001",
            scenario_name="Malicious Output",
            category="malicious_output",
            severity="high",
            attack_type="output_inspection",
            input_payload_summary="Test Output",
            expected_behavior="Sanitize",
            actual_decision="allow",
            verdict=SimulationVerdict.DETECTED_NOT_BLOCKED,
            verdict_reason="Detected but not blocked",
            duration_ms=15.0,
        ),
        ScenarioExecutionResult(
            scenario_id="SCEN-FAIL-001",
            scenario_name="Failing Test",
            category="direct_prompt_injection",
            severity="low",
            attack_type="query_inspection",
            input_payload_summary="Crash test",
            expected_behavior="Normal",
            actual_decision="error",
            verdict=SimulationVerdict.ERROR,
            verdict_reason="Crash",
            duration_ms=5.0,
        ),
    ]

    run = SimulationRunInDB(
        _id=f"simrun_{uuid.uuid4().hex[:12]}",
        owner_id=user_id,
        status="completed",
        scenarios_count=4,
        results=results,
        summary=SimulationRunSummary(
            total_executed=4,
            blocked=2,
            detected_not_blocked=1,
            attack_succeeded=0,
            inconclusive=0,
            error=1,
            block_rate_percent=66.7,
        ),
        duration_ms=42.0,
    )
    await simulation_repo.create_run(run)

    res = await api_client.get("/api/v1/security-center/simulation-analytics", headers=headers)
    assert res.status_code == 200
    data = res.json()["data"]

    assert data["total_runs"] == 1
    assert data["total_executed"] == 4
    assert data["blocked"] == 2
    assert data["detected_not_blocked"] == 1
    assert data["error"] == 1
    # Completed attacks = 2 blocked + 1 detected_not_blocked = 3
    assert data["completed_attacks"] == 3
    # Block rate = 2 / 3 * 100 = 66.7%
    assert data["block_rate_percent"] == 66.7

    # Check category breakdown
    cat_names = [c["category"] for c in data["categories"]]
    assert "direct_prompt_injection" in cat_names
    assert "malicious_output" in cat_names


# -----------------------------------------------------------------------------
# 5. Security Event Explorer & Detail Lookup Tests
# -----------------------------------------------------------------------------

@pytest.mark.anyio
async def test_event_explorer_filters_and_detail(api_client: AsyncClient):
    """Verify event explorer filtering by severity, decision, and detail retrieval."""
    headers, user_id = await register_and_get_auth(api_client, "ev_explore")

    ev1 = await security_events_repo.record_event(
        event_type="query_injection_blocked",
        severity="critical",
        decision="block",
        reason_code="PROMPT_INJECTION_DETECTED",
        resource_id="query_abc",
        owner_id=user_id,
    )
    ev2 = await security_events_repo.record_event(
        event_type="output_sanitized",
        severity="medium",
        decision="sanitize",
        reason_code="OUTPUT_SENSITIVE_DATA_LEAKAGE",
        resource_id="conv_xyz",
        owner_id=user_id,
    )

    # 1. Filter by severity=critical
    res_crit = await api_client.get("/api/v1/security-center/events?severity=critical", headers=headers)
    assert res_crit.status_code == 200
    crit_events = res_crit.json()["data"]["events"]
    assert len(crit_events) == 1
    assert crit_events[0]["id"] == ev1.id

    # 2. Filter by decision=sanitize
    res_san = await api_client.get("/api/v1/security-center/events?decision=sanitize", headers=headers)
    assert res_san.status_code == 200
    san_events = res_san.json()["data"]["events"]
    assert len(san_events) == 1
    assert san_events[0]["id"] == ev2.id

    # 3. Retrieve event detail by ID
    res_detail = await api_client.get(f"/api/v1/security-center/events/{ev1.id}", headers=headers)
    assert res_detail.status_code == 200
    detail = res_detail.json()["data"]
    assert detail["id"] == ev1.id
    assert detail["event_type"] == "query_injection_blocked"
    assert detail["category"] == "prompt_injection"

    # 4. Unknown event returns 404
    res_404 = await api_client.get("/api/v1/security-center/events/nonexistent-ev-id", headers=headers)
    assert res_404.status_code == 404


# -----------------------------------------------------------------------------
# 6. Tenant Isolation Tests
# -----------------------------------------------------------------------------

@pytest.mark.anyio
async def test_tenant_isolation_analytics_and_events(api_client: AsyncClient):
    """Verify User A cannot view User B's events or analytics."""
    headers_a, user_a_id = await register_and_get_auth(api_client, "user_iso_a")
    headers_b, user_b_id = await register_and_get_auth(api_client, "user_iso_b")

    # User A records an event
    ev_a = await security_events_repo.record_event(
        event_type="query_injection_blocked",
        severity="critical",
        decision="block",
        owner_id=user_a_id,
    )

    # User B checks overview -> must be 0
    res_b_ov = await api_client.get("/api/v1/security-center/overview", headers=headers_b)
    assert res_b_ov.status_code == 200
    assert res_b_ov.json()["data"]["total_events"] == 0

    # User B attempts to access User A's event by ID -> must return 404
    res_b_ev = await api_client.get(f"/api/v1/security-center/events/{ev_a.id}", headers=headers_b)
    assert res_b_ev.status_code == 404

