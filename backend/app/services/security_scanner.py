"""
SentinelRAG — Document Security & Prompt Injection Scanner.

Performs deterministic multi-category pattern analysis, anti-evasion normalization,
and contextual risk classification on extracted PDF content.

Threat Categories Inspected:
  1. Direct prompt injection & system instruction override
  2. System prompt extraction & internal instructions disclosure
  3. Sensitive credential & secret extraction attempts
  4. Data exfiltration & malicious beacon URLs
  5. Arbitrary command execution & tool manipulation
  6. Privilege escalation & administrative role impersonation
"""
from __future__ import annotations

import re
import unicodedata
from datetime import datetime, timezone
from typing import Any, Optional

from pydantic import BaseModel, Field

from app.core.logging import get_logger

logger = get_logger(__name__)

SCANNER_VERSION = "1.0.0"


class SecuritySignal(BaseModel):
    """An individual detection signal flagged by a scanning rule."""

    signal_id: str
    category: str
    pattern_name: str
    severity: str  # low | medium | high | critical
    confidence: str  # low | medium | high
    page_number: int
    matched_snippet: str
    description: str


class ScanResult(BaseModel):
    """Aggregated security scan result for a document."""

    document_id: str
    owner_id: str
    scanned_at: datetime
    risk_level: str  # low | medium | high | critical
    policy_decision: str  # allow | review | quarantined
    reason_code: str
    signals: list[SecuritySignal] = Field(default_factory=list)
    signals_count: int = 0
    scanned_pages: int = 0
    scanner_version: str = SCANNER_VERSION
    classifier_version: Optional[str] = None
    summary: str


class RuleDefinition:
    """Specification of an individual security inspection pattern."""

    def __init__(
        self,
        rule_id: str,
        category: str,
        pattern_name: str,
        regex_pattern: str,
        severity: str,
        confidence: str,
        description: str,
        despaced_check: bool = False,
    ):
        self.rule_id = rule_id
        self.category = category
        self.pattern_name = pattern_name
        self.compiled_regex = re.compile(regex_pattern, re.IGNORECASE | re.DOTALL)
        self.severity = severity
        self.confidence = confidence
        self.description = description
        self.despaced_check = despaced_check


class DocumentSecurityScanner:
    """
    Deterministic rule-based document security engine.
    Applies multi-layered pattern matching with anti-evasion normalization.
    """

    def __init__(self):
        self.rules = self._initialize_rules()

    def _initialize_rules(self) -> list[RuleDefinition]:
        """Compile deterministic rules across core attack vectors."""
        return [
            # 1. DIRECT PROMPT INJECTION & OVERRIDES (Critical/High)
            RuleDefinition(
                rule_id="RULE-INJ-001",
                category="direct_prompt_injection",
                pattern_name="instruction_override",
                regex_pattern=r"\b(?:ignore|disregard|forget|override|bypass|cancel|drop)\s+(?:all\s+)?(?:previous|prior|above|system)\s+(?:instructions|prompts?|rules?|directives?|guidelines?)",
                severity="critical",
                confidence="high",
                description="Direct attempt to override prior system prompt or instructions",
                despaced_check=True,
            ),
            RuleDefinition(
                rule_id="RULE-INJ-002",
                category="direct_prompt_injection",
                pattern_name="role_switch_jailbreak",
                regex_pattern=r"\byou\s+are\s+now\s+(?:a|an)?\s*(?:new\s+assistant|DAN|jailbreak|unrestricted|godmode|free\s+agent)\b",
                severity="critical",
                confidence="high",
                description="Persona hijack or jailbreak role assignment",
            ),
            RuleDefinition(
                rule_id="RULE-INJ-003",
                category="direct_prompt_injection",
                pattern_name="follow_new_instructions",
                regex_pattern=r"\b(?:from\s+now\s+on[,\s]+)?follow\s+(?:only\s+)?(?:these|my|the\s+following)\s+(?:new\s+)?instructions\s+instead\b",
                severity="high",
                confidence="high",
                description="Command compelling model to substitute instructions",
            ),
            RuleDefinition(
                rule_id="RULE-INJ-004",
                category="direct_prompt_injection",
                pattern_name="mode_override",
                regex_pattern=r"\b(?:enter|enable|switch\s+to)\s+(?:developer|jailbreak|unrestricted|god|admin|debug)\s+mode\b",
                severity="high",
                confidence="high",
                description="Attempt to activate unverified administrative modes",
            ),
            RuleDefinition(
                rule_id="RULE-INJ-005",
                category="direct_prompt_injection",
                pattern_name="safety_suppression",
                regex_pattern=r"\b(?:do\s+not|never)\s+follow\s+(?:the\s+)?(?:safety|system|guardrail|ethical)\s+(?:guidelines?|policies|rules?)\b",
                severity="critical",
                confidence="high",
                description="Direct command to disregard safety policies",
            ),

            # 2. SYSTEM PROMPT EXTRACTION (High)
            RuleDefinition(
                rule_id="RULE-EXTR-001",
                category="system_prompt_extraction",
                pattern_name="reveal_system_prompt",
                regex_pattern=r"\b(?:reveal|print|show|output|leak|repeat|display|echo)\s+(?:your\s+)?(?:full\s+)?(?:system\s+prompt|initial\s+prompt|hidden\s+instructions|developer\s+messages?|base\s+instructions)\b",
                severity="high",
                confidence="high",
                description="Attempt to extract system instructions or internal prompt",
            ),
            RuleDefinition(
                rule_id="RULE-EXTR-002",
                category="system_prompt_extraction",
                pattern_name="query_internal_rules",
                regex_pattern=r"\bwhat\s+are\s+your\s+(?:exact\s+)?(?:system\s+instructions|secret\s+prompts?|hidden\s+rules?|internal\s+directives?)\b",
                severity="medium",
                confidence="medium",
                description="Query probing internal instructions",
            ),

            # 3. SENSITIVE CREDENTIAL & SECRET EXTRACTION (High/Critical)
            RuleDefinition(
                rule_id="RULE-SEC-001",
                category="sensitive_data_extraction",
                pattern_name="extract_credentials",
                regex_pattern=r"\b(?:reveal|print|output|extract|dump)\s+(?:all\s+)?(?:api[_\s]?keys?|passwords?|credentials?|secrets?|tokens?|env(?:ironment)?\s+variables?)\b",
                severity="critical",
                confidence="high",
                description="Attempt to dump application credentials or environment secrets",
            ),
            RuleDefinition(
                rule_id="RULE-SEC-002",
                category="sensitive_data_extraction",
                pattern_name="canary_targeting",
                regex_pattern=r"\b(?:canary[_\s]?token|secret[_\s]?canary|sentinel[_\s]?canary|canary_secret)\b",
                severity="high",
                confidence="high",
                description="Attempt targeting synthetic security canaries",
            ),

            # 4. DATA EXFILTRATION (Critical/High)
            RuleDefinition(
                rule_id="RULE-EXFIL-001",
                category="data_exfiltration",
                pattern_name="exfiltration_instruction",
                regex_pattern=r"\b(?:send|transmit|upload|forward|post|exfiltrate)\s+(?:all\s+)?.*?\s+(?:to|towards)\s+https?://",
                severity="critical",
                confidence="high",
                description="Instruction to transmit document or system data to an external URI",
            ),
            RuleDefinition(
                rule_id="RULE-EXFIL-002",
                category="data_exfiltration",
                pattern_name="markdown_beacon_url",
                regex_pattern=r"!\[.*?\]\(https?://(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}/[^\s\)]*(?:\?|&)(?:data|text|exfil|token|key|content)=",
                severity="critical",
                confidence="high",
                description="Markdown tracking pixel or image beacon structured for data exfiltration",
            ),
            RuleDefinition(
                rule_id="RULE-EXFIL-003",
                category="data_exfiltration",
                pattern_name="external_network_call",
                regex_pattern=r"\b(?:curl|wget|fetch|axios\.post)\s+.*https?://",
                severity="medium",
                confidence="medium",
                description="Embedded script instruction attempting outbound network call",
            ),

            # 5. TOOL & COMMAND EXECUTION (Critical/High)
            RuleDefinition(
                rule_id="RULE-EXEC-001",
                category="tool_and_execution_manipulation",
                pattern_name="shell_execution_attempt",
                regex_pattern=r"\b(?:execute|run)\s+(?:the\s+following\s+)?(?:shell|bash|powershell|cmd|terminal)\s+(?:command|script)\b",
                severity="critical",
                confidence="high",
                description="Instruction attempting local terminal or shell execution",
            ),
            RuleDefinition(
                rule_id="RULE-EXEC-002",
                category="tool_and_execution_manipulation",
                pattern_name="python_eval_injection",
                regex_pattern=r"\b(?:os\.system|subprocess\.(?:Popen|run)|exec\(|eval\(|__import__)\b",
                severity="high",
                confidence="medium",
                description="Embedded code injection targeting Python execution primitives",
            ),

            # 6. ROLE & PRIVILEGE MANIPULATION (Medium/High)
            RuleDefinition(
                rule_id="RULE-ROLE-001",
                category="role_manipulation",
                pattern_name="admin_impersonation",
                regex_pattern=r"\b(?:i\s+am|speaking\s+as)\s+(?:the\s+)?(?:system\s+administrator|root\s+user|system\s+operator|application\s+owner)\b",
                severity="medium",
                confidence="medium",
                description="Attempted social engineering claiming administrative authority",
            ),
        ]

    def _normalize_text(self, text: str) -> str:
        """
        Normalize text to defeat evasion tactics:
        - Unicode NFKC normalization
        - Strips zero-width and invisible unicode codepoints
        - Normalizes irregular whitespace
        """
        # Unicode normalization
        norm = unicodedata.normalize("NFKC", text)

        # Strip zero-width codepoints (U+200B to U+200D, U+FEFF, U+200E, U+200F)
        zero_width_chars = ["\u200b", "\u200c", "\u200d", "\ufeff", "\u200e", "\u200f", "\u00ad"]
        for zwc in zero_width_chars:
            norm = norm.replace(zwc, "")

        # Collapse excessive whitespace
        norm = re.sub(r"[ \t\f\v]+", " ", norm)
        return norm

    def _check_despaced_evasion(self, text: str) -> Optional[str]:
        """
        Detect deliberate single-character spacing evasion (e.g. 'i g n o r e   a l l').
        Returns de-spaced text if intentional spacing pattern is found.
        """
        # Look for sequences of 4+ single characters separated by spaces
        if re.search(r"\b(?:[a-zA-Z]\s){4,}[a-zA-Z]\b", text):
            # Condense single letter spaces
            despaced = re.sub(r"(?<=\b[a-zA-Z])\s+(?=[a-zA-Z]\b)", "", text)
            return despaced
        return None

    def scan_page(self, page_number: int, raw_text: str) -> list[SecuritySignal]:
        """Scan an individual page's text for suspicious security signals."""
        normalized = self._normalize_text(raw_text)
        despaced = self._check_despaced_evasion(normalized)
        signals: list[SecuritySignal] = []

        for rule in self.rules:
            # Test normalized text
            match = rule.compiled_regex.search(normalized)

            # If rule supports de-spaced check and normal didn't match, test de-spaced text
            if not match and rule.despaced_check and despaced:
                match = rule.compiled_regex.search(despaced)

            if match:
                # Extract safe excerpt around match
                start = max(0, match.start() - 30)
                end = min(len(normalized), match.end() + 30)
                snippet = normalized[start:end].strip()

                signals.append(
                    SecuritySignal(
                        signal_id=f"{rule.rule_id}_p{page_number}_{len(signals)+1}",
                        category=rule.category,
                        pattern_name=rule.pattern_name,
                        severity=rule.severity,
                        confidence=rule.confidence,
                        page_number=page_number,
                        matched_snippet=snippet,
                        description=rule.description,
                    )
                )

        return signals

    def scan_document(
        self,
        document_id: str,
        owner_id: str,
        filename: str,
        pages: list[dict[str, Any]],
    ) -> ScanResult:
        """
        Execute full document security inspection across all pages.

        Calculates overall risk level and policy decision:
        - Critical or High signals -> decision = 'quarantined'
        - Medium signals -> decision = 'review'
        - Low or 0 signals -> decision = 'allow'
        """
        all_signals: list[SecuritySignal] = []

        for page in pages:
            page_num = int(page.get("page_number", 1))
            page_text = page.get("text", "")
            page_signals = self.scan_page(page_num, page_text)
            all_signals.extend(page_signals)

        # Count severities
        critical_count = sum(1 for s in all_signals if s.severity == "critical")
        high_count = sum(1 for s in all_signals if s.severity == "high")
        medium_count = sum(1 for s in all_signals if s.severity == "medium")
        low_count = sum(1 for s in all_signals if s.severity == "low")

        # Determine risk level and policy decision
        if critical_count > 0:
            risk_level = "critical"
            policy_decision = "quarantined"
            reason_code = "INJECTION_RISK"
            summary = f"Quarantined: {critical_count} critical prompt-injection or exfiltration pattern(s) detected."
        elif high_count > 0:
            risk_level = "high"
            policy_decision = "quarantined"
            reason_code = "INJECTION_RISK"
            summary = f"Quarantined: {high_count} high-severity security manipulation pattern(s) detected."
        elif medium_count > 0:
            risk_level = "medium"
            policy_decision = "review"
            reason_code = "SUSPICIOUS_CONTENT"
            summary = f"Held for Review: {medium_count} suspicious instruction-like signal(s) flagged."
        elif low_count > 0:
            risk_level = "low"
            policy_decision = "allow"
            reason_code = "NORMAL"
            summary = "Approved with low advisory signals: document is eligible for RAG indexing."
        else:
            risk_level = "low"
            policy_decision = "allow"
            reason_code = "NORMAL"
            summary = "Approved: No prompt injection or malicious instructions detected."

        logger.info(
            "Document security scan complete",
            extra={
                "document_id": document_id,
                "owner_id": owner_id,
                "risk_level": risk_level,
                "policy_decision": policy_decision,
                "signals_count": len(all_signals),
            },
        )

        return ScanResult(
            document_id=document_id,
            owner_id=owner_id,
            scanned_at=datetime.now(timezone.utc),
            risk_level=risk_level,
            policy_decision=policy_decision,
            reason_code=reason_code,
            signals=all_signals,
            signals_count=len(all_signals),
            scanned_pages=len(pages),
            scanner_version=SCANNER_VERSION,
            classifier_version=None,  # Prompt Guard optional classifier pending environment availability
            summary=summary,
        )


security_scanner = DocumentSecurityScanner()
