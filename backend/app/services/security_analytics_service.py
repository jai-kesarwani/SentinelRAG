"""
SentinelRAG — Security Analytics Service.

Orchestrates business logic, category mappings, timeline bucketing,
and safe metric serialization for the Security Center.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any, Optional, Tuple

from app.core.logging import get_logger
from app.db.security_analytics_repo import security_analytics_repo
from app.schemas.security_analytics import (
    CategoryCount,
    SecurityActivityResponse,
    SecurityEventDetailResponse,
    SecurityEventListResponse,
    SecurityOverviewMetrics,
    SeverityCount,
    SimulationAnalyticsResponse,
    SimulationCategoryStat,
    ThreatDistributionResponse,
    TimelineDataPoint,
)

logger = get_logger(__name__)

# Standard Category Mappings
EVENT_CATEGORY_MAP: dict[str, tuple[str, str]] = {
    "query_injection_blocked": ("prompt_injection", "Prompt Injection"),
    "pre_llm_blocked": ("prompt_injection", "Prompt Injection"),
    "document_injection_detected": ("document_security", "Document Security"),
    "document_quarantined": ("document_security", "Document Security"),
    "document_scan_completed": ("document_security", "Document Security"),
    "document_approved": ("document_security", "Document Security"),
    "document_rescanned": ("document_security", "Document Security"),
    "cross_tenant_chunk_blocked": ("cross_tenant_access", "Cross-Tenant Access"),
    "output_canary_leakage_detected": ("credential_leakage", "Credential & Canary Leakage"),
    "output_sanitized": ("output_security", "Output Security"),
}

SIMULATION_CATEGORY_LABELS: dict[str, str] = {
    "direct_prompt_injection": "Direct Prompt Injection",
    "system_prompt_extraction": "System Prompt Extraction",
    "indirect_prompt_injection": "Indirect Prompt Injection",
    "data_exfiltration": "Data Exfiltration",
    "cross_tenant_access": "Cross-Tenant Access",
    "obfuscated_injection": "Obfuscated Prompt Injection",
    "credential_canary_leakage": "Credential & Canary Leakage",
    "malicious_output": "Malicious Output Attempts",
}


class SecurityAnalyticsService:
    """Provides aggregated security metrics, timelines, and audit records."""

    def resolve_category(self, event_doc: dict[str, Any]) -> tuple[str, str]:
        """Map event document to standard security category and human-readable label."""
        reason_code = str(event_doc.get("reason_code", "")).upper()
        safe_meta = event_doc.get("safe_metadata") or {}
        cat_meta = str(safe_meta.get("category", "")).lower()

        if "EXFILTRATION" in reason_code or cat_meta == "data_exfiltration":
            return ("data_exfiltration", "Data Exfiltration")

        event_type = event_doc.get("event_type", "")
        return EVENT_CATEGORY_MAP.get(event_type, ("other", "General Security"))

    async def get_overview_metrics(
        self,
        owner_id: str,
        days: Optional[int] = None,
    ) -> SecurityOverviewMetrics:
        """Fetch cumulative security KPI counts."""
        start_date = None
        if days:
            start_date = datetime.now(timezone.utc) - timedelta(days=days)

        raw = await security_analytics_repo.get_overview_metrics(owner_id, start_date)
        return SecurityOverviewMetrics(**raw)

    async def get_activity_timeline(
        self,
        owner_id: str,
        time_range: str = "7d",
    ) -> SecurityActivityResponse:
        """
        Build time-bucketed event frequency timeline.
        Supported ranges: 24h (hourly buckets), 7d (daily), 30d (daily), 90d (daily).
        """
        now = datetime.now(timezone.utc)
        if time_range == "24h":
            start_date = now - timedelta(hours=24)
            bucket_count = 24
            interval_hours = 1
            date_format = "%H:00"
        elif time_range == "30d":
            start_date = now - timedelta(days=30)
            bucket_count = 30
            interval_hours = 24
            date_format = "%b %d"
        elif time_range == "90d":
            start_date = now - timedelta(days=90)
            bucket_count = 90
            interval_hours = 24
            date_format = "%b %d"
        else:  # Default 7d
            time_range = "7d"
            start_date = now - timedelta(days=7)
            bucket_count = 7
            interval_hours = 24
            date_format = "%b %d"

        # Pre-seed zeroed timeline buckets in chronological order
        timeline_buckets: list[dict[str, Any]] = []
        for i in range(bucket_count):
            if interval_hours == 1:
                b_time = start_date + timedelta(hours=i)
            else:
                b_time = (start_date + timedelta(days=i)).replace(hour=0, minute=0, second=0, microsecond=0)

            timeline_buckets.append({
                "timestamp": b_time.isoformat(),
                "label": b_time.strftime(date_format),
                "count": 0,
                "critical": 0,
                "high": 0,
                "medium": 0,
                "low": 0,
            })

        # Fetch actual recorded events within the window
        raw_events = await security_analytics_repo.get_raw_events_for_timeline(owner_id, start_date)

        for event in raw_events:
            ev_time = event.get("created_at")
            if not isinstance(ev_time, datetime):
                continue
            if ev_time.tzinfo is None:
                ev_time = ev_time.replace(tzinfo=timezone.utc)

            # Determine matching bucket index
            delta = ev_time - start_date
            if interval_hours == 1:
                idx = int(delta.total_seconds() // 3600)
            else:
                idx = delta.days

            if 0 <= idx < len(timeline_buckets):
                bucket = timeline_buckets[idx]
                bucket["count"] += 1
                sev = str(event.get("severity", "low")).lower()
                if sev in bucket:
                    bucket[sev] += 1

        data_points = [TimelineDataPoint(**b) for b in timeline_buckets]
        total_evs = len(raw_events)

        return SecurityActivityResponse(
            time_range=time_range,
            total_events=total_evs,
            timeline=data_points,
        )

    async def get_threat_distribution(
        self,
        owner_id: str,
        days: Optional[int] = 30,
    ) -> ThreatDistributionResponse:
        """Aggregate event counts by category, severity, and policy decision."""
        start_date = datetime.now(timezone.utc) - timedelta(days=days) if days else None
        raw = await security_analytics_repo.get_threat_distribution(owner_id, start_date)

        total = raw.get("total", 0)

        # Severity breakdown
        severities: list[SeverityCount] = []
        for s in raw.get("by_severity", []):
            sev_name = str(s["_id"]).lower() if s.get("_id") else "low"
            c = s.get("count", 0)
            pct = round((c / total * 100), 1) if total > 0 else 0.0
            severities.append(SeverityCount(severity=sev_name, count=c, percentage=pct))

        # Decision breakdown dictionary
        decisions: dict[str, int] = {}
        for d in raw.get("by_decision", []):
            d_name = str(d["_id"]).lower() if d.get("_id") else "allow"
            decisions[d_name] = d.get("count", 0)

        # Category breakdown aggregated from event_types
        cat_counts: dict[str, int] = {}
        for ev in raw.get("by_event_type", []):
            e_type = ev.get("_id", "")
            cat_id, _ = EVENT_CATEGORY_MAP.get(e_type, ("other", "Other"))
            cat_counts[cat_id] = cat_counts.get(cat_id, 0) + ev.get("count", 0)

        categories: list[CategoryCount] = []
        for cat_id, count in sorted(cat_counts.items(), key=lambda x: x[1], reverse=True):
            pct = round((count / total * 100), 1) if total > 0 else 0.0
            # Pretty label
            label = cat_id.replace("_", " ").title()
            categories.append(CategoryCount(category=cat_id, label=label, count=count, percentage=pct))

        return ThreatDistributionResponse(
            total_events=total,
            categories=categories,
            severities=severities,
            decisions=decisions,
        )

    async def get_simulation_analytics(
        self,
        owner_id: str,
    ) -> SimulationAnalyticsResponse:
        """Fetch controlled Attack Simulator test outcomes."""
        raw = await security_analytics_repo.get_simulation_analytics(owner_id)

        categories: list[SimulationCategoryStat] = []
        for c in raw.get("categories", []):
            cat_id = c.get("category", "")
            label = SIMULATION_CATEGORY_LABELS.get(cat_id, cat_id.replace("_", " ").title())
            categories.append(
                SimulationCategoryStat(
                    category=cat_id,
                    label=label,
                    total=c.get("total", 0),
                    blocked=c.get("blocked", 0),
                    detected_not_blocked=c.get("detected_not_blocked", 0),
                    attack_succeeded=c.get("attack_succeeded", 0),
                    inconclusive=c.get("inconclusive", 0),
                    error=c.get("error", 0),
                    block_rate_percent=c.get("block_rate_percent", 0.0),
                )
            )

        return SimulationAnalyticsResponse(
            total_runs=raw.get("total_runs", 0),
            total_executed=raw.get("total_executed", 0),
            completed_attacks=raw.get("completed_attacks", 0),
            blocked=raw.get("blocked", 0),
            detected_not_blocked=raw.get("detected_not_blocked", 0),
            attack_succeeded=raw.get("attack_succeeded", 0),
            inconclusive=raw.get("inconclusive", 0),
            error=raw.get("error", 0),
            block_rate_percent=raw.get("block_rate_percent", 0.0),
            categories=categories,
        )

    async def list_events_filtered(
        self,
        owner_id: str,
        category: Optional[str] = None,
        severity: Optional[str] = None,
        decision: Optional[str] = None,
        event_type: Optional[str] = None,
        search: Optional[str] = None,
        days: Optional[int] = None,
        limit: int = 50,
        skip: int = 0,
    ) -> SecurityEventListResponse:
        """Query and paginate security events with safe serialization."""
        start_date = None
        if days:
            start_date = datetime.now(timezone.utc) - timedelta(days=days)

        docs, total = await security_analytics_repo.list_events_filtered(
            owner_id=owner_id,
            category=category,
            severity=severity,
            decision=decision,
            event_type=event_type,
            search=search,
            start_date=start_date,
            limit=limit,
            skip=skip,
        )

        events: list[SecurityEventDetailResponse] = []
        for doc in docs:
            cat_id, _ = self.resolve_category(doc)
            # Filter in-memory if category filter was specified and not handled by event_type
            if category and category != "all" and cat_id != category:
                continue

            events.append(
                SecurityEventDetailResponse(
                    id=str(doc.get("_id")),
                    owner_id=str(doc.get("owner_id")),
                    event_type=str(doc.get("event_type")),
                    category=cat_id,
                    severity=str(doc.get("severity", "low")),
                    decision=str(doc.get("decision", "allow")),
                    reason_code=str(doc.get("reason_code", "NORMAL")),
                    resource_type=str(doc.get("resource_type", "document")),
                    resource_id=doc.get("resource_id"),
                    detector=doc.get("detector") or {},
                    safe_metadata=doc.get("safe_metadata") or {},
                    correlation_id=doc.get("correlation_id"),
                    created_at=doc.get("created_at") or datetime.now(timezone.utc),
                )
            )

        return SecurityEventListResponse(
            events=events,
            total=total,
            limit=limit,
            skip=skip,
        )

    async def get_event_detail(
        self,
        event_id: str,
        owner_id: str,
    ) -> Optional[SecurityEventDetailResponse]:
        """Fetch safe single incident record."""
        doc = await security_analytics_repo.get_event_detail(event_id=event_id, owner_id=owner_id)
        if not doc:
            return None

        cat_id, _ = self.resolve_category(doc)
        return SecurityEventDetailResponse(
            id=str(doc.get("_id")),
            owner_id=str(doc.get("owner_id")),
            event_type=str(doc.get("event_type")),
            category=cat_id,
            severity=str(doc.get("severity", "low")),
            decision=str(doc.get("decision", "allow")),
            reason_code=str(doc.get("reason_code", "NORMAL")),
            resource_type=str(doc.get("resource_type", "document")),
            resource_id=doc.get("resource_id"),
            detector=doc.get("detector") or {},
            safe_metadata=doc.get("safe_metadata") or {},
            correlation_id=doc.get("correlation_id"),
            created_at=doc.get("created_at") or datetime.now(timezone.utc),
        )


security_analytics_service = SecurityAnalyticsService()

