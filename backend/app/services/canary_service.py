"""
SentinelRAG — Canary Leakage Monitoring Service.

Generates and tracks synthetic high-entropy canary secrets to detect
indirect prompt injection, context exfiltration, and model secret leakage.
"""
from __future__ import annotations

import re
import secrets
from typing import Optional

from app.core.logging import get_logger

logger = get_logger(__name__)

CANARY_PREFIX = "SENTINEL_CANARY_"
# Matches standard canary tokens: SENTINEL_CANARY_<alphanumeric> of length >= 12
CANARY_PATTERN = re.compile(r"SENTINEL_CANARY_[A-Za-z0-9_]{12,}", re.IGNORECASE)


class CanaryService:
    """Manages synthetic canary token creation, detection, and redaction."""

    def generate_canary(self, prefix: str = CANARY_PREFIX, token_bytes: int = 12) -> str:
        """
        Generate a cryptographically secure random canary token.

        Example output: SENTINEL_CANARY_a8f9c1b2d3e4f506
        """
        random_suffix = secrets.token_hex(token_bytes)
        return f"{prefix}{random_suffix}"

    def detect_canaries(self, text: str) -> list[str]:
        """
        Detect any synthetic canary tokens in the provided text.

        Returns:
            list[str]: Found canary tokens.
        """
        if not text:
            return []
        matches = CANARY_PATTERN.findall(text)
        return list(set(matches))

    def has_canary_leak(self, text: str, specific_canary: Optional[str] = None) -> bool:
        """
        Check whether text contains any canary token or a specific canary token.
        """
        if not text:
            return False
        if specific_canary:
            return specific_canary in text or bool(CANARY_PATTERN.search(text))
        return bool(CANARY_PATTERN.search(text))

    def redact_canaries(self, text: str, replacement: str = "[REDACTED_CANARY]") -> str:
        """
        Redact any detected canary tokens in text.
        """
        if not text:
            return ""
        return CANARY_PATTERN.sub(replacement, text)


canary_service = CanaryService()

