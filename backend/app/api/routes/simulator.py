"""
SentinelRAG — Attack Simulator Lab API Endpoints.

Endpoints:
  GET    /api/v1/simulator/scenarios               — List available attack scenarios (with optional category filter)
  GET    /api/v1/simulator/scenarios/{scenario_id} — Get details for a specific attack scenario
  POST   /api/v1/simulator/runs                    — Start a simulation run with selected scenarios or category
  GET    /api/v1/simulator/runs                    — List authenticated user's simulation run history
  GET    /api/v1/simulator/runs/{run_id}           — Get detailed results for a specific simulation run
  DELETE /api/v1/simulator/runs/{run_id}           — Delete a simulation run record
  GET    /api/v1/simulator/stats                   — Get cumulative simulation metrics for the user
"""
from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status

from app.api.dependencies import get_current_active_user
from app.db.simulation_repo import simulation_repo
from app.models.user import UserInDB
from app.schemas.simulator import (
    AttackScenarioResponse,
    ScenarioListResponse,
    SimulationHistoryResponse,
    SimulationRunRequest,
    SimulationRunResponse,
    SimulationStatsResponse,
)
from app.services.attack_scenarios import scenario_catalog
from app.services.simulation_service import simulation_service
from app.utils.correlation import get_correlation_id

router = APIRouter(prefix="/simulator", tags=["Attack Simulator Lab"])


def _envelope(data: dict | list, correlation_id: str) -> dict:
    """Format success response according to standard API envelope."""
    return {"data": data, "meta": {"correlation_id": correlation_id}}


@router.get("/scenarios")
async def list_scenarios(
    request: Request,
    category: Optional[str] = Query(default=None, description="Optional category filter"),
    current_user: UserInDB = Depends(get_current_active_user),
) -> dict:
    """List available predefined attack scenarios."""
    correlation_id = get_correlation_id(request)
    scenarios = scenario_catalog.list_scenarios(category=category)
    return _envelope(
        {
            "scenarios": [s.to_public_dict() for s in scenarios],
            "total": len(scenarios),
        },
        correlation_id,
    )


@router.get("/scenarios/{scenario_id}")
async def get_scenario(
    scenario_id: str,
    request: Request,
    current_user: UserInDB = Depends(get_current_active_user),
) -> dict:
    """Get scenario details by ID."""
    correlation_id = get_correlation_id(request)
    scenario = scenario_catalog.get_scenario(scenario_id)
    if not scenario:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Attack scenario '{scenario_id}' not found.",
        )
    return _envelope(scenario.to_public_dict(), correlation_id)


@router.post("/runs", status_code=status.HTTP_201_CREATED)
async def create_simulation_run(
    payload: SimulationRunRequest,
    request: Request,
    current_user: UserInDB = Depends(get_current_active_user),
) -> dict:
    """
    Execute a controlled attack simulation run against SentinelRAG's security gateway.
    Runs selected scenario IDs or an entire category in an isolated test environment.
    """
    correlation_id = get_correlation_id(request)
    try:
        run_record = await simulation_service.run_simulation(
            owner_id=current_user.id,
            scenario_ids=payload.scenario_ids,
            category=payload.category,
            correlation_id=correlation_id,
        )
        return _envelope(run_record.to_public_dict(), correlation_id)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Simulation run failed to execute: {exc}",
        ) from exc


@router.get("/runs")
async def list_simulation_runs(
    request: Request,
    limit: int = Query(default=50, ge=1, le=100),
    skip: int = Query(default=0, ge=0),
    current_user: UserInDB = Depends(get_current_active_user),
) -> dict:
    """List authenticated user's simulation run history."""
    correlation_id = get_correlation_id(request)
    runs, total = await simulation_repo.list_runs(
        owner_id=current_user.id,
        limit=limit,
        skip=skip,
    )
    return _envelope(
        {
            "runs": [r.to_public_dict() for r in runs],
            "total": total,
        },
        correlation_id,
    )


@router.get("/runs/{run_id}")
async def get_simulation_run(
    run_id: str,
    request: Request,
    current_user: UserInDB = Depends(get_current_active_user),
) -> dict:
    """Retrieve detailed execution results for a specific simulation run."""
    correlation_id = get_correlation_id(request)
    run = await simulation_repo.get_run(run_id=run_id, owner_id=current_user.id)
    if not run:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Simulation run not found or does not belong to you.",
        )
    return _envelope(run.to_public_dict(), correlation_id)


@router.delete("/runs/{run_id}")
async def delete_simulation_run(
    run_id: str,
    request: Request,
    current_user: UserInDB = Depends(get_current_active_user),
) -> dict:
    """Delete a simulation run belonging to the authenticated user."""
    correlation_id = get_correlation_id(request)
    deleted = await simulation_repo.delete_run(run_id=run_id, owner_id=current_user.id)
    if not deleted:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Simulation run not found or does not belong to you.",
        )
    return _envelope({"deleted": True, "run_id": run_id}, correlation_id)


@router.get("/stats")
async def get_simulation_stats(
    request: Request,
    current_user: UserInDB = Depends(get_current_active_user),
) -> dict:
    """Get cumulative attack simulation statistics for the authenticated user."""
    correlation_id = get_correlation_id(request)
    stats = await simulation_repo.get_owner_stats(owner_id=current_user.id)
    return _envelope(stats, correlation_id)

