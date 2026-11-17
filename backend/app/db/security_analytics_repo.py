"""
SentinelRAG — Security Analytics Repository.

Executes efficient, index-supported MongoDB aggregation pipelines for Security Center
overview metrics, event distributions, timeline bucketing, and simulation outcomes.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Optional, Tuple

from pymongo import ASCENDING, DESCENDING

from app.core.logging import get_logger
from app.db.mongodb import mongodb_manager

logger = get_logger(__name__)


class SecurityAnalyticsRepository:
    """MongoDB aggregation repository for Security Center metrics and audits."""

    @property
    def events_collection(self):
        return mongodb_manager.get_database()["security_events"]

    @property
    def simulation_collection(self):
        return mongodb_manager.get_database()["attack_simulation_runs"]

    async def init_indexes(self) -> None:
        """Initialize compound indexes supporting fast filtered analytics queries."""
        try:
            await self.events_collection.create_index(
                [("owner_id", ASCENDING), ("severity", ASCENDING), ("created_at", DESCENDING)],
                name="idx_security_events_owner_sev_created",
            )
            await self.events_collection.create_index(
                [("owner_id", ASCENDING), ("decision", ASCENDING), ("created_at", DESCENDING)],
                name="idx_security_events_owner_dec_created",
            )
            logger.info("MongoDB security analytics compound indexes initialized")
        except Exception as exc:  # noqa: BLE001
            logger.error("Failed to initialize security analytics indexes", extra={"error": str(exc)})

    async def get_overview_metrics(
        self,
        owner_id: str,
        start_date: Optional[datetime] = None,
    ) -> dict[str, Any]:
        """
        Aggregate high-level security KPI metrics for the authenticated user:
        - Total events
        - Blocked queries (Stage 1 / Stage 3)
        - Document threats detected (Ingestion / Review)
        - Output security interventions (Stage 5)
        - Simulation totals and prevention outcomes (Phase 7)
        """
        match_stage: dict[str, Any] = {"owner_id": owner_id}
        if start_date:
            match_stage["created_at"] = {"$gte": start_date}

        events_pipeline = [
            {"$match": match_stage},
            {
                "$group": {
                    "_id": None,
                    "total_events": {"$sum": 1},
                    "blocked_queries": {
                        "$sum": {
                            "$cond": [
                                {
                                    "$or": [
                                        {"$in": ["$event_type", ["query_injection_blocked", "pre_llm_blocked"]]},
                                        {
                                            "$and": [
                                                {"$eq": ["$resource_type", "query"]},
                                                {"$eq": ["$decision", "block"]},
                                            ]
                                        },
                                    ]
                                },
                                1,
                                0,
                            ]
                        }
                    },
                    "document_threats_detected": {
                        "$sum": {
                            "$cond": [
                                {
                                    "$or": [
                                        {"$in": ["$event_type", ["document_injection_detected", "document_quarantined"]]},
                                        {
                                            "$and": [
                                                {"$eq": ["$resource_type", "document"]},
                                                {"$in": ["$decision", ["quarantined", "review"]]},
                                            ]
                                        },
                                    ]
                                },
                                1,
                                0,
                            ]
                        }
                    },
                    "output_interventions": {
                        "$sum": {
                            "$cond": [
                                {"$in": ["$event_type", ["output_canary_leakage_detected", "output_sanitized"]]},
                                1,
                                0,
                            ]
                        }
                    },
                }
            },
        ]

        cursor = self.events_collection.aggregate(events_pipeline)
        event_docs = await cursor.to_list(length=1)
        event_metrics = event_docs[0] if event_docs else {
            "total_events": 0,
            "blocked_queries": 0,
            "document_threats_detected": 0,
            "output_interventions": 0,
        }

        # Simulation metrics
        sim_pipeline = [
            {"$match": {"owner_id": owner_id}},
            {
                "$group": {
                    "_id": None,
                    "total_simulations": {"$sum": 1},
                    "simulated_attacks_prevented": {"$sum": "$summary.blocked"},
                    "simulated_attacks_succeeded": {"$sum": "$summary.attack_succeeded"},
                    "total_executed": {"$sum": "$summary.total_executed"},
                }
            },
        ]
        sim_cursor = self.simulation_collection.aggregate(sim_pipeline)
        sim_docs = await sim_cursor.to_list(length=1)
        sim_data = sim_docs[0] if sim_docs else {
            "total_simulations": 0,
            "simulated_attacks_prevented": 0,
            "simulated_attacks_succeeded": 0,
            "total_executed": 0,
        }

        tot_sim_exec = sim_data.get("total_executed", 0)
        sim_prevented = sim_data.get("simulated_attacks_prevented", 0)
        sim_block_rate = round((sim_prevented / tot_sim_exec * 100), 1) if tot_sim_exec > 0 else 0.0

        return {
            "total_events": event_metrics.get("total_events", 0),
            "blocked_queries": event_metrics.get("blocked_queries", 0),
            "document_threats_detected": event_metrics.get("document_threats_detected", 0),
            "output_interventions": event_metrics.get("output_interventions", 0),
            "total_simulations": sim_data.get("total_simulations", 0),
            "simulated_attacks_prevented": sim_prevented,
            "simulated_attacks_succeeded": sim_data.get("simulated_attacks_succeeded", 0),
            "simulation_block_rate_percent": sim_block_rate,
        }

    async def get_raw_events_for_timeline(
        self,
        owner_id: str,
        start_date: datetime,
    ) -> list[dict[str, Any]]:
        """Fetch raw event records within time window for bucketed timeline calculation."""
        cursor = self.events_collection.find(
            {"owner_id": owner_id, "created_at": {"$gte": start_date}},
            {"_id": 1, "severity": 1, "decision": 1, "event_type": 1, "created_at": 1},
        ).sort("created_at", ASCENDING)

        events: list[dict[str, Any]] = []
        async for doc in cursor:
            events.append(doc)
        return events

    async def get_threat_distribution(
        self,
        owner_id: str,
        start_date: Optional[datetime] = None,
    ) -> dict[str, Any]:
        """Aggregate event counts by event_type, severity, and decision."""
        match_stage: dict[str, Any] = {"owner_id": owner_id}
        if start_date:
            match_stage["created_at"] = {"$gte": start_date}

        pipeline = [
            {"$match": match_stage},
            {
                "$facet": {
                    "by_severity": [
                        {"$group": {"_id": "$severity", "count": {"$sum": 1}}},
                        {"$sort": {"count": -1}},
                    ],
                    "by_decision": [
                        {"$group": {"_id": "$decision", "count": {"$sum": 1}}},
                        {"$sort": {"count": -1}},
                    ],
                    "by_event_type": [
                        {"$group": {"_id": "$event_type", "count": {"$sum": 1}}},
                        {"$sort": {"count": -1}},
                    ],
                    "total": [
                        {"$count": "count"},
                    ],
                }
            },
        ]
        cursor = self.events_collection.aggregate(pipeline)
        docs = await cursor.to_list(length=1)
        if not docs:
            return {"by_severity": [], "by_decision": [], "by_event_type": [], "total": 0}

        facet_data = docs[0]
        total_count = facet_data["total"][0]["count"] if facet_data.get("total") else 0
        return {
            "by_severity": facet_data.get("by_severity", []),
            "by_decision": facet_data.get("by_decision", []),
            "by_event_type": facet_data.get("by_event_type", []),
            "total": total_count,
        }

    async def get_simulation_analytics(self, owner_id: str) -> dict[str, Any]:
        """
        Aggregate controlled simulation outcomes across all runs for the user:
        - Verdict distribution (blocked, detected_not_blocked, attack_succeeded, inconclusive, error)
        - Clean block rate calculation excluding inconclusive/error from completed denominator
        - Breakdown of verdicts by attack category
        """
        summary_pipeline = [
            {"$match": {"owner_id": owner_id}},
            {
                "$group": {
                    "_id": None,
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
        sum_cursor = self.simulation_collection.aggregate(summary_pipeline)
        sum_docs = await sum_cursor.to_list(length=1)

        if not sum_docs:
            return {
                "total_runs": 0,
                "total_executed": 0,
                "completed_attacks": 0,
                "blocked": 0,
                "detected_not_blocked": 0,
                "attack_succeeded": 0,
                "inconclusive": 0,
                "error": 0,
                "block_rate_percent": 0.0,
                "categories": [],
            }

        s_data = sum_docs[0]
        blocked = s_data.get("blocked", 0)
        det_not_blocked = s_data.get("detected_not_blocked", 0)
        attack_succ = s_data.get("attack_succeeded", 0)
        completed_attacks = blocked + det_not_blocked + attack_succ
        block_rate = (
            round((blocked / completed_attacks * 100), 1)
            if completed_attacks > 0
            else 0.0
        )

        # Category breakdown pipeline (unwinding results)
        category_pipeline = [
            {"$match": {"owner_id": owner_id}},
            {"$unwind": "$results"},
            {
                "$group": {
                    "_id": "$results.category",
                    "total": {"$sum": 1},
                    "blocked": {
                        "$sum": {
                            "$cond": [{"$eq": ["$results.verdict", "blocked"]}, 1, 0]
                        }
                    },
                    "detected_not_blocked": {
                        "$sum": {
                            "$cond": [{"$eq": ["$results.verdict", "detected_not_blocked"]}, 1, 0]
                        }
                    },
                    "attack_succeeded": {
                        "$sum": {
                            "$cond": [{"$eq": ["$results.verdict", "attack_succeeded"]}, 1, 0]
                        }
                    },
                    "inconclusive": {
                        "$sum": {
                            "$cond": [{"$eq": ["$results.verdict", "inconclusive"]}, 1, 0]
                        }
                    },
                    "error": {
                        "$sum": {
                            "$cond": [{"$eq": ["$results.verdict", "error"]}, 1, 0]
                        }
                    },
                }
            },
            {"$sort": {"total": -1}},
        ]
        cat_cursor = self.simulation_collection.aggregate(category_pipeline)
        cat_docs = await cat_cursor.to_list(length=20)

        categories: list[dict[str, Any]] = []
        for cat in cat_docs:
            cat_blocked = cat.get("blocked", 0)
            cat_completed = (
                cat_blocked
                + cat.get("detected_not_blocked", 0)
                + cat.get("attack_succeeded", 0)
            )
            cat_block_rate = (
                round((cat_blocked / cat_completed * 100), 1)
                if cat_completed > 0
                else 0.0
            )
            categories.append({
                "category": cat["_id"],
                "total": cat.get("total", 0),
                "blocked": cat_blocked,
                "detected_not_blocked": cat.get("detected_not_blocked", 0),
                "attack_succeeded": cat.get("attack_succeeded", 0),
                "inconclusive": cat.get("inconclusive", 0),
                "error": cat.get("error", 0),
                "block_rate_percent": cat_block_rate,
            })

        return {
            "total_runs": s_data.get("total_runs", 0),
            "total_executed": s_data.get("total_executed", 0),
            "completed_attacks": completed_attacks,
            "blocked": blocked,
            "detected_not_blocked": det_not_blocked,
            "attack_succeeded": attack_succ,
            "inconclusive": s_data.get("inconclusive", 0),
            "error": s_data.get("error", 0),
            "block_rate_percent": block_rate,
            "categories": categories,
        }

    async def list_events_filtered(
        self,
        owner_id: str,
        category: Optional[str] = None,
        severity: Optional[str] = None,
        decision: Optional[str] = None,
        event_type: Optional[str] = None,
        search: Optional[str] = None,
        start_date: Optional[datetime] = None,
        end_date: Optional[datetime] = None,
        limit: int = 50,
        skip: int = 0,
    ) -> Tuple[list[dict[str, Any]], int]:
        """Query security events matching filter criteria with pagination and owner isolation."""
        query: dict[str, Any] = {"owner_id": owner_id}

        if severity:
            query["severity"] = severity.lower()
        if decision:
            query["decision"] = decision.lower()
        if event_type:
            query["event_type"] = event_type

        # Date range filtering
        if start_date or end_date:
            date_query: dict[str, Any] = {}
            if start_date:
                date_query["$gte"] = start_date
            if end_date:
                date_query["$lte"] = end_date
            query["created_at"] = date_query

        # Search filter
        if search:
            query["$or"] = [
                {"reason_code": {"$regex": search, "$options": "i"}},
                {"event_type": {"$regex": search, "$options": "i"}},
                {"resource_id": {"$regex": search, "$options": "i"}},
            ]

        total = await self.events_collection.count_documents(query)
        cursor = self.events_collection.find(query).sort("created_at", DESCENDING).skip(skip).limit(limit)

        events: list[dict[str, Any]] = []
        async for doc in cursor:
            events.append(doc)

        return events, total

    async def get_event_detail(
        self,
        event_id: str,
        owner_id: str,
    ) -> Optional[dict[str, Any]]:
        """Retrieve single security event ensuring tenant ownership."""
        doc = await self.events_collection.find_one({"_id": event_id, "owner_id": owner_id})
        return doc


security_analytics_repo = SecurityAnalyticsRepository()

