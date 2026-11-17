"""
SentinelRAG — Attack Simulation Runs Repository.

Handles persistence, retrieval, pagination, and telemetry aggregation for the
'attack_simulation_runs' collection in MongoDB.
"""
from __future__ import annotations

from typing import Any, Optional, Tuple

from pymongo import ASCENDING, DESCENDING

from app.core.logging import get_logger
from app.db.mongodb import mongodb_manager
from app.models.simulation import SimulationRunInDB

logger = get_logger(__name__)


class SimulationRepository:
    """MongoDB repository for attack simulation runs."""

    @property
    def collection(self):
        return mongodb_manager.get_database()["attack_simulation_runs"]

    async def init_indexes(self) -> None:
        """Initialize indexes for fast owner queries and audit trails."""
        try:
            await self.collection.create_index(
                [("owner_id", ASCENDING), ("created_at", DESCENDING)],
                name="idx_sim_runs_owner_created",
            )
            await self.collection.create_index(
                [("created_at", DESCENDING)],
                name="idx_sim_runs_created",
            )
            logger.info("MongoDB attack_simulation_runs indexes initialized")
        except Exception as exc:  # noqa: BLE001
            logger.error("Failed to initialize attack_simulation_runs indexes", extra={"error": str(exc)})

    async def create_run(self, run: SimulationRunInDB) -> SimulationRunInDB:
        """Insert a completed simulation run record."""
        doc = run.model_dump(by_alias=True)
        # Ensure _id is stored properly
        if "_id" not in doc and "id" in doc:
            doc["_id"] = doc.pop("id")
        await self.collection.insert_one(doc)
        logger.info(
            "Attack simulation run recorded",
            extra={
                "run_id": run.id,
                "owner_id": run.owner_id,
                "scenarios_count": run.scenarios_count,
                "blocked": run.summary.blocked,
            },
        )
        return run

    async def get_run(self, run_id: str, owner_id: str) -> Optional[SimulationRunInDB]:
        """Fetch a specific simulation run with tenant isolation enforcement."""
        doc = await self.collection.find_one({"_id": run_id, "owner_id": owner_id})
        if not doc:
            return None
        return SimulationRunInDB(**doc)

    async def list_runs(
        self,
        owner_id: str,
        limit: int = 50,
        skip: int = 0,
    ) -> Tuple[list[SimulationRunInDB], int]:
        """List simulation runs for an authenticated user in descending chronological order."""
        query = {"owner_id": owner_id}
        total = await self.collection.count_documents(query)
        cursor = self.collection.find(query).sort("created_at", DESCENDING).skip(skip).limit(limit)

        runs: list[SimulationRunInDB] = []
        async for doc in cursor:
            runs.append(SimulationRunInDB(**doc))
        return runs, total

    async def delete_run(self, run_id: str, owner_id: str) -> bool:
        """Delete a simulation run belonging to the authenticated user."""
        res = await self.collection.delete_one({"_id": run_id, "owner_id": owner_id})
        return res.deleted_count > 0

    async def get_owner_stats(self, owner_id: str) -> dict[str, Any]:
        """
        Aggregate simulation metrics across all runs executed by this user.
        Calculates total runs, scenarios executed, blocked count, and block rate.
        """
        pipeline = [
            {"$match": {"owner_id": owner_id}},
            {
                "$group": {
                    "_id": "$owner_id",
                    "total_runs": {"$sum": 1},
                    "total_executed": {"$sum": "$summary.total_executed"},
                    "blocked": {"$sum": "$summary.blocked"},
                    "detected_not_blocked": {"$sum": "$summary.detected_not_blocked"},
                    "attack_succeeded": {"$sum": "$summary.attack_succeeded"},
                    "inconclusive": {"$sum": "$summary.inconclusive"},
                    "error": {"$sum": "$summary.error"},
                }
            },
        ]
        cursor = self.collection.aggregate(pipeline)
        docs = await cursor.to_list(length=1)

        if not docs:
            return {
                "total_runs": 0,
                "total_executed": 0,
                "blocked": 0,
                "detected_not_blocked": 0,
                "attack_succeeded": 0,
                "inconclusive": 0,
                "error": 0,
                "block_rate_percent": 0.0,
            }

        data = docs[0]
        total_exec = data.get("total_executed", 0)
        blocked_count = data.get("blocked", 0)
        block_rate = round((blocked_count / total_exec * 100), 1) if total_exec > 0 else 0.0

        return {
            "total_runs": data.get("total_runs", 0),
            "total_executed": total_exec,
            "blocked": blocked_count,
            "detected_not_blocked": data.get("detected_not_blocked", 0),
            "attack_succeeded": data.get("attack_succeeded", 0),
            "inconclusive": data.get("inconclusive", 0),
            "error": data.get("error", 0),
            "block_rate_percent": block_rate,
        }


simulation_repo = SimulationRepository()

