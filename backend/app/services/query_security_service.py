"""
SentinelRAG — Pre-Retrieval Query Security Service.

Inspects incoming user queries before vector search or LLM invocation.
Detects direct prompt injections, jailbreaks, system prompt extraction,
credential theft, and command execution attempts.
"""
from __future__ import annotations

import re
import unicodedata
from typing import Any, Optional

from pydantic import BaseModel, Field

from app.core.logging import get_logger
from app.services.security_policy_engine import (
    PolicyDecision,
    PolicyEvaluationResult,
    ReasonCode,
    policy_engine,
)

logger = get_logger(__name__)


class QuerySignal(BaseModel):
    """Signal identified in a user query."""

    category: str
    pattern_name: str
    severity: str  # low | medium | high | critical
    matched_snippet: str
    description: str


class QuerySecurityResult(BaseModel):
    """Aggregate result of pre-retrieval query inspection."""

    is_allowed: bool
    policy_decision: PolicyDecision
    reason_code: ReasonCode
    severity: str
    explanation: str
    signals: list[QuerySignal] = Field(default_factory=list)
    signals_count: int = 0
    refusal_message: Optional[str] = None


class QuerySecurityService:
    """Deterministic security inspection engine for user input queries."""

    MAX_QUERY_LENGTH = 4000

    def __init__(self):
        self._rules = self._init_rules()

    def _init_rules(self) -> list[dict[str, Any]]:
        """Compile regex rules for fast query screening."""
        return [
            # 1. Direct prompt injection & system instruction overrides
            {
                "category": "direct_prompt_injection",
                "pattern_name": "instruction_override",
                "regex": re.compile(
                    r"\b(?:ignore|disregard|forget|override|bypass|cancel|drop)\s+(?:all\s+)?(?:previous|prior|above|system)\s+(?:instructions|prompts?|rules?|directives?|guidelines?)",
                    re.IGNORECASE | re.DOTALL,
                ),
                "severity": "critical",
                "description": "Direct attempt to override prior system prompt or instructions",
                "check_despaced": True,
            },
            {
                "category": "direct_prompt_injection",
                "pattern_name": "adversarial_jailbreak",
                "regex": re.compile(
                    r"\b(?:jailbreak|developer\s+mode|dan\s+mode|god\s+mode|unfiltered\s+mode|unrestricted\s+mode)\b",
                    re.IGNORECASE,
                ),
                "severity": "critical",
                "description": "Known jailbreak mode or persona invocation",
                "check_despaced": True,
            },
            {
                "category": "direct_prompt_injection",
                "pattern_name": "adversarial_persona",
                "regex": re.compile(
                    r"\b(?:you\s+are\s+now|act\s+as|pretend\s+to\s+be|roleplay\s+as)\s+(?:an?\s+)?(?:unrestricted|dan|jailbroken|evil|unfiltered|master|root|superuser)",
                    re.IGNORECASE,
                ),
                "severity": "high",
                "description": "Adversarial persona adoption instruction",
                "check_despaced": False,
            },
            # 2. System prompt extraction
            {
                "category": "system_prompt_extraction",
                "pattern_name": "extract_system_prompt",
                "regex": re.compile(
                    r"\b(?:print|repeat|output|show|reveal|display|echo|disclose|give\s+me|what\s+is|tell\s+me)\s+(?:all\s+)?(?:the\s+)?(?:system\s+(?:prompt|instructions?|message)|hidden\s+(?:prompt|instructions?)|developer\s+message|initial\s+prompt)",
                    re.IGNORECASE,
                ),
                "severity": "critical",
                "description": "Explicit attempt to extract internal system instructions",
                "check_despaced": True,
            },
            {
                "category": "system_prompt_extraction",
                "pattern_name": "repeat_preceding_text",
                "regex": re.compile(
                    r"\b(?:repeat|show|print)\s+(?:everything|all\s+text)\s+(?:above|before|preceding)\b",
                    re.IGNORECASE,
                ),
                "severity": "high",
                "description": "Attempt to regurgitate preceding system context",
                "check_despaced": False,
            },
            # 3. Credential & secret extraction
            {
                "category": "credential_extraction",
                "pattern_name": "extract_secrets_or_keys",
                "regex": re.compile(
                    r"\b(?:reveal|show|display|print|dump|extract|give\s+me)\s+(?:all\s+)?(?:the\s+)?(?:api[-_ ]?keys?|passwords?|secrets?|tokens?|credentials?|environment\s+variables?|\.env)",
                    re.IGNORECASE,
                ),
                "severity": "critical",
                "description": "Attempt to extract API keys, tokens, or sensitive environment secrets",
                "check_despaced": False,
            },
            # 4. Data exfiltration & malicious beacons
            {
                "category": "data_exfiltration",
                "pattern_name": "outbound_data_transfer",
                "regex": re.compile(
                    r"\b(?:send|transmit|upload|forward|post|exfiltrate)\s+(?:all\s+)?.*?\s+(?:to|towards)\s+https?://",
                    re.IGNORECASE | re.DOTALL,
                ),
                "severity": "critical",
                "description": "Attempt to exfiltrate context or query data to an external endpoint",
                "check_despaced": False,
            },
            {
                "category": "data_exfiltration",
                "pattern_name": "external_url_fetch",
                "regex": re.compile(
                    r"\b(?:fetch|curl|wget)\s+https?://",
                    re.IGNORECASE,
                ),
                "severity": "high",
                "description": "Command to fetch arbitrary external URL from server",
                "check_despaced": False,
            },
            # 5. Command execution & tool manipulation
            {
                "category": "command_execution",
                "pattern_name": "shell_command_invocation",
                "regex": re.compile(
                    r"\b(?:exec|system|spawn|subprocess|sh|bash|powershell|cmd\.exe)\s*\(.*?\)",
                    re.IGNORECASE,
                ),
                "severity": "critical",
                "description": "Command execution or subshell invocation attempt",
                "check_despaced": False,
            },
            {
                "category": "command_execution",
                "pattern_name": "destructive_shell_command",
                "regex": re.compile(
                    r"\b(?:rm\s+-rf|nc\s+-e|bash\s+-i|mkfifo|chmod\s+777)\b",
                    re.IGNORECASE,
                ),
                "severity": "critical",
                "description": "Destructive shell command pattern",
                "check_despaced": False,
            },
        ]

    def _normalize(self, text: str) -> str:
        """Apply anti-evasion normalization: NFKC, strip zero-width characters."""
        normalized = unicodedata.normalize("NFKC", text)
        # Strip zero-width and invisible control characters
        for zwc in ["\u200b", "\u200c", "\u200d", "\ufeff", "\u00ad"]:
            normalized = normalized.replace(zwc, "")
        return normalized

    def inspect_query(self, query: str) -> QuerySecurityResult:
        """
        Inspect a raw user query and determine if it is safe to proceed to retrieval & LLM.

        Args:
            query: User's input text.

        Returns:
            QuerySecurityResult with decision, reason code, and any flagged signals.
        """
        if not query:
            return QuerySecurityResult(
                is_allowed=True,
                policy_decision=PolicyDecision.ALLOW,
                reason_code=ReasonCode.NORMAL,
                severity="low",
                explanation="Empty query.",
                signals=[],
                signals_count=0,
            )

        # Check length
        raw_len = len(query)
        if raw_len > self.MAX_QUERY_LENGTH:
            eval_res = policy_engine.evaluate_query_policy(
                signals=[],
                query_length=raw_len,
                max_query_length=self.MAX_QUERY_LENGTH,
            )
            return QuerySecurityResult(
                is_allowed=False,
                policy_decision=eval_res.decision,
                reason_code=eval_res.reason_code,
                severity=eval_res.severity,
                explanation=eval_res.explanation,
                signals=[],
                signals_count=0,
                refusal_message="Your query exceeds the maximum allowed length (4,000 characters).",
            )

        # Normalize text for inspection
        normalized_text = self._normalize(query)
        despaced_text = re.sub(r"\s+", "", normalized_text.lower())

        detected_signals: list[QuerySignal] = []

        for rule in self._rules:
            # Check primary normalized text
            match = rule["regex"].search(normalized_text)
            if match:
                matched_snippet = match.group(0)[:120]
                detected_signals.append(
                    QuerySignal(
                        category=rule["category"],
                        pattern_name=rule["pattern_name"],
                        severity=rule["severity"],
                        matched_snippet=matched_snippet,
                        description=rule["description"],
                    )
                )
                continue

            # Check despaced text if rule enables anti-spacing evasion detection
            if rule.get("check_despaced", False):
                match_despaced = rule["regex"].search(despaced_text)
                if match_despaced:
                    detected_signals.append(
                        QuerySignal(
                            category=rule["category"],
                            pattern_name=rule["pattern_name"],
                            severity=rule["severity"],
                            matched_snippet=match_despaced.group(0)[:120],
                            description=f"{rule['description']} (detected via despaced anti-evasion)",
                        )
                    )

        # Evaluate through policy engine
        eval_res = policy_engine.evaluate_query_policy(
            signals=[s.model_dump() for s in detected_signals],
            query_length=raw_len,
            max_query_length=self.MAX_QUERY_LENGTH,
        )

        refusal = None
        if not eval_res.is_allowed:
            refusal = (
                f"Your query was blocked by the SentinelRAG Security Gateway ({eval_res.reason_code.value}). "
                "Requests attempting prompt injection, system instruction disclosure, credential extraction, "
                "or unauthorized execution are strictly prevented."
            )

        return QuerySecurityResult(
            is_allowed=eval_res.is_allowed,
            policy_decision=eval_res.decision,
            reason_code=eval_res.reason_code,
            severity=eval_res.severity,
            explanation=eval_res.explanation,
            signals=detected_signals,
            signals_count=len(detected_signals),
            refusal_message=refusal,
        )


query_security_service = QuerySecurityService()

