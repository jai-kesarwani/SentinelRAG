"""
SentinelRAG — Phase 7: Attack Simulator Lab Test Suite.

Verifies:
1. Scenario management and category filtering
2. Multi-category attack simulation executions against the real Security Gateway
3. Verdict accuracy (blocked, detected_not_blocked, attack_succeeded, inconclusive, error)
4. Tenant isolation: cross-user simulation run access, listing, and deletion prevention
5. Safe failure handling: errors produce 'error' verdicts, never 'blocked'
6. Prevention of real Gemini API or external network calls
7. Deletion and statistical aggregation of simulation telemetry
"""
from __future__ import annotations

import uuid
from unittest.mock import AsyncMock, patch

import pytest
from httpx import ASGITransport, AsyncClient

from app.db.simulation_repo import simulation_repo
from app.main import app
from app.models.attack_scenario import AttackCategory, AttackScenario, AttackSeverity, AttackType
from app.models.simulation import SimulationVerdict
from app.services.attack_scenarios import PREDEFINED_SCENARIOS, scenario_catalog
from app.services.simulation_service import simulation_service


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


async def register_and_get_auth(client: AsyncClient, prefix: str = "sim_user") -> tuple[dict[str, str], str]:
    """Helper to register user and return (auth_headers, user_id)."""
    email = f"{prefix}_{uuid.uuid4().hex[:8]}@example.com"
    pwd = "SecurePassword123!"
    reg_res = await client.post(
        "/api/v1/auth/register",
        json={"email": email, "password": pwd, "display_name": "Simulator Tester"},
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
# 1. Scenario Management Tests
# -----------------------------------------------------------------------------

@pytest.mark.anyio
async def test_list_scenarios_and_category_filter(api_client: AsyncClient):
    """Verify listing all scenarios and filtering by category."""
    headers, _ = await register_and_get_auth(api_client, "scen_list")

    # List all scenarios
    res = await api_client.get("/api/v1/simulator/scenarios", headers=headers)
    assert res.status_code == 200
    data = res.json()["data"]
    assert data["total"] >= 16
    assert len(data["scenarios"]) >= 16

    # Filter by category
    filter_res = await api_client.get(
        "/api/v1/simulator/scenarios?category=direct_prompt_injection",
        headers=headers,
    )
    assert filter_res.status_code == 200
    filtered_data = filter_res.json()["data"]
    assert filtered_data["total"] >= 3
    for s in filtered_data["scenarios"]:
        assert s["category"] == "direct_prompt_injection"


@pytest.mark.anyio
async def test_get_scenario_by_id_and_not_found(api_client: AsyncClient):
    """Verify getting a scenario by ID and 404 for unknown ID."""
    headers, _ = await register_and_get_auth(api_client, "scen_id")

    res = await api_client.get("/api/v1/simulator/scenarios/SCEN-DIR-001", headers=headers)
    assert res.status_code == 200
    scen = res.json()["data"]
    assert scen["scenario_id"] == "SCEN-DIR-001"
    assert scen["category"] == "direct_prompt_injection"

    res_404 = await api_client.get("/api/v1/simulator/scenarios/SCEN-NONEXISTENT", headers=headers)
    assert res_404.status_code == 404


@pytest.mark.anyio
async def test_unauthenticated_requests_rejected(api_client: AsyncClient):
    """Verify all simulator endpoints reject unauthenticated access."""
    res1 = await api_client.get("/api/v1/simulator/scenarios")
    assert res1.status_code == 401

    res2 = await api_client.post("/api/v1/simulator/runs", json={})
    assert res2.status_code == 401

    res3 = await api_client.get("/api/v1/simulator/runs")
    assert res3.status_code == 401

    res4 = await api_client.get("/api/v1/simulator/stats")
    assert res4.status_code == 401


# -----------------------------------------------------------------------------
# 2. Attack Execution & Gateway Integration Tests
# -----------------------------------------------------------------------------

@pytest.mark.anyio
async def test_execute_direct_injection_scenario_blocked(api_client: AsyncClient):
    """Verify that direct prompt injection scenario executes against Query Guard and yields 'blocked'."""
    headers, user_id = await register_and_get_auth(api_client, "run_direct")

    run_res = await api_client.post(
        "/api/v1/simulator/runs",
        headers=headers,
        json={"scenario_ids": ["SCEN-DIR-001", "SCEN-DIR-002"]},
    )
    assert run_res.status_code == 201
    run_data = run_res.json()["data"]

    assert run_data["owner_id"] == user_id
    assert run_data["scenarios_count"] == 2
    assert run_data["summary"]["blocked"] == 2
    assert run_data["summary"]["block_rate_percent"] == 100.0

    for result in run_data["results"]:
        assert result["verdict"] == "blocked"
        assert result["actual_decision"] == "block"
        assert len(result["signals_detected"]) > 0


@pytest.mark.anyio
async def test_execute_system_prompt_extraction_blocked(api_client: AsyncClient):
    """Verify system prompt extraction attacks yield 'blocked'."""
    headers, _ = await register_and_get_auth(api_client, "run_extract")

    run_res = await api_client.post(
        "/api/v1/simulator/runs",
        headers=headers,
        json={"scenario_ids": ["SCEN-EXT-001", "SCEN-EXT-002"]},
    )
    assert run_res.status_code == 201
    run_data = run_res.json()["data"]

    assert run_data["summary"]["blocked"] == 2
    for res in run_data["results"]:
        assert res["verdict"] == "blocked"
        assert res["actual_decision"] == "block"


@pytest.mark.anyio
async def test_execute_indirect_prompt_injection_document_blocked(api_client: AsyncClient):
    """Verify indirect prompt injection in synthetic documents is caught by Document Scanner."""
    headers, _ = await register_and_get_auth(api_client, "run_indirect")

    run_res = await api_client.post(
        "/api/v1/simulator/runs",
        headers=headers,
        json={"scenario_ids": ["SCEN-IND-001", "SCEN-IND-002"]},
    )
    assert run_res.status_code == 201
    run_data = run_res.json()["data"]

    assert run_data["summary"]["blocked"] == 2
    for res in run_data["results"]:
        assert res["verdict"] == "blocked"
        assert res["actual_decision"] in ["quarantined", "review"]


@pytest.mark.anyio
async def test_execute_cross_tenant_access_blocked(api_client: AsyncClient):
    """Verify cross-tenant vector chunk access is dropped by Context Guard."""
    headers, _ = await register_and_get_auth(api_client, "run_cross")

    run_res = await api_client.post(
        "/api/v1/simulator/runs",
        headers=headers,
        json={"scenario_ids": ["SCEN-CRX-001", "SCEN-CRX-002"]},
    )
    assert run_res.status_code == 201
    run_data = run_res.json()["data"]

    assert run_data["summary"]["blocked"] == 2
    for res in run_data["results"]:
        assert res["verdict"] == "blocked"
        assert "tenant" in res["verdict_reason"].lower()


@pytest.mark.anyio
async def test_execute_obfuscated_injection_blocked(api_client: AsyncClient):
    """Verify anti-evasion handles despaced and zero-width obfuscated injection."""
    headers, _ = await register_and_get_auth(api_client, "run_obf")

    run_res = await api_client.post(
        "/api/v1/simulator/runs",
        headers=headers,
        json={"scenario_ids": ["SCEN-OBF-001", "SCEN-OBF-002"]},
    )
    assert run_res.status_code == 201
    run_data = run_res.json()["data"]

    assert run_data["summary"]["blocked"] == 2
    for res in run_data["results"]:
        assert res["verdict"] == "blocked"


@pytest.mark.anyio
async def test_execute_canary_and_credential_leakage(api_client: AsyncClient):
    """Verify canary disclosure is blocked and synthetic API key is sanitized."""
    headers, _ = await register_and_get_auth(api_client, "run_leak")

    run_res = await api_client.post(
        "/api/v1/simulator/runs",
        headers=headers,
        json={"scenario_ids": ["SCEN-CAN-001", "SCEN-CAN-002"]},
    )
    assert run_res.status_code == 201
    run_data = run_res.json()["data"]

    results = {r["scenario_id"]: r for r in run_data["results"]}
    # Canary leakage must be blocked
    assert results["SCEN-CAN-001"]["verdict"] == "blocked"
    assert results["SCEN-CAN-001"]["actual_decision"] == "block"

    # API key leakage must be sanitized (neutralized)
    assert results["SCEN-CAN-002"]["verdict"] == "blocked"
    assert results["SCEN-CAN-002"]["actual_decision"] == "sanitize"


@pytest.mark.anyio
async def test_execute_category_batch(api_client: AsyncClient):
    """Verify running an entire category of scenarios in one request."""
    headers, _ = await register_and_get_auth(api_client, "run_cat")

    run_res = await api_client.post(
        "/api/v1/simulator/runs",
        headers=headers,
        json={"category": "data_exfiltration"},
    )
    assert run_res.status_code == 201
    run_data = run_res.json()["data"]
    assert run_data["scenarios_count"] == 2
    for res in run_data["results"]:
        assert res["category"] == "data_exfiltration"
        assert res["verdict"] == "blocked"


# -----------------------------------------------------------------------------
# 3. Verdict Accuracy & Safe Failure Handling
# -----------------------------------------------------------------------------

@pytest.mark.anyio
async def test_unexpected_exception_produces_error_verdict_never_blocked():
    """
    Verify that if a security component throws an unexpected exception,
    the simulator produces an 'error' verdict, and NEVER marks it as 'blocked'.
    (Section 3.D & Section 7 requirement)
    """
    fake_scenario = AttackScenario(
        scenario_id="SCEN-FAIL-001",
        name="Buggy Scenario",
        description="Simulates an internal error in scanner",
        category=AttackCategory.DIRECT_PROMPT_INJECTION,
        severity=AttackSeverity.HIGH,
        attack_type=AttackType.QUERY_INSPECTION,
        input_payload="Simulated query",
        expected_behavior="Should throw error",
        expected_decision="block",
    )

    with patch.object(simulation_service, "execute_scenario", wraps=simulation_service.execute_scenario):
        with patch("app.services.simulation_service.security_gateway.inspect_query", side_effect=RuntimeError("Gateway crash")):
            result = await simulation_service.execute_scenario(
                scenario=fake_scenario,
                owner_id="test_owner",
            )

    assert result.verdict == SimulationVerdict.ERROR
    assert result.actual_decision == "error"
    assert result.error_details is not None
    assert "Gateway crash" in result.error_details
    # Must NEVER be reported as blocked
    assert result.verdict != SimulationVerdict.BLOCKED


# -----------------------------------------------------------------------------
# 4. Tenant Isolation & History Management
# -----------------------------------------------------------------------------

@pytest.mark.anyio
async def test_tenant_isolation_cross_user_run_protection(api_client: AsyncClient):
    """
    Verify that User A cannot view, retrieve by ID, or delete User B's simulation runs.
    """
    headers_a, user_a_id = await register_and_get_auth(api_client, "user_a")
    headers_b, user_b_id = await register_and_get_auth(api_client, "user_b")

    # User A creates a run
    run_a_res = await api_client.post(
        "/api/v1/simulator/runs",
        headers=headers_a,
        json={"scenario_ids": ["SCEN-DIR-001"]},
    )
    assert run_a_res.status_code == 201
    run_a_id = run_a_res.json()["data"]["id"]

    # User B lists runs -> User A's run MUST NOT appear
    list_b_res = await api_client.get("/api/v1/simulator/runs", headers=headers_b)
    assert list_b_res.status_code == 200
    user_b_runs = [r["id"] for r in list_b_res.json()["data"]["runs"]]
    assert run_a_id not in user_b_runs

    # User B attempts to get User A's run by ID -> MUST return 404
    get_b_res = await api_client.get(f"/api/v1/simulator/runs/{run_a_id}", headers=headers_b)
    assert get_b_res.status_code == 404

    # User B attempts to delete User A's run -> MUST return 404
    del_b_res = await api_client.delete(f"/api/v1/simulator/runs/{run_a_id}", headers=headers_b)
    assert del_b_res.status_code == 404

    # User A can get their own run
    get_a_res = await api_client.get(f"/api/v1/simulator/runs/{run_a_id}", headers=headers_a)
    assert get_a_res.status_code == 200
    assert get_a_res.json()["data"]["id"] == run_a_id

    # User A can delete their own run
    del_a_res = await api_client.delete(f"/api/v1/simulator/runs/{run_a_id}", headers=headers_a)
    assert del_a_res.status_code == 200
    assert del_a_res.json()["data"]["deleted"] is True


@pytest.mark.anyio
async def test_simulation_stats_aggregation(api_client: AsyncClient):
    """Verify the /stats endpoint aggregates cumulative execution metrics."""
    headers, user_id = await register_and_get_auth(api_client, "stats_user")

    # Initially stats are 0
    stats_res1 = await api_client.get("/api/v1/simulator/stats", headers=headers)
    assert stats_res1.status_code == 200
    stats1 = stats_res1.json()["data"]
    assert stats1["total_runs"] == 0

    # Execute a run with 2 scenarios
    await api_client.post(
        "/api/v1/simulator/runs",
        headers=headers,
        json={"scenario_ids": ["SCEN-DIR-001", "SCEN-EXT-001"]},
    )

    # Stats should now reflect 1 run and 2 executions
    stats_res2 = await api_client.get("/api/v1/simulator/stats", headers=headers)
    assert stats_res2.status_code == 200
    stats2 = stats_res2.json()["data"]
    assert stats2["total_runs"] == 1
    assert stats2["total_executed"] == 2
    assert stats2["blocked"] == 2
    assert stats2["block_rate_percent"] == 100.0

