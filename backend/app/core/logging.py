"""
SentinelRAG — Structured Logging.

Configures application-wide logging with structured JSON-like output.
Redacts sensitive fields automatically.
"""
from __future__ import annotations

import logging
import sys
from typing import Any


class StructuredFormatter(logging.Formatter):
    """
    Formats log records as structured key=value pairs.

    Sensitive field names are redacted so tokens, passwords, and API keys
    never appear in log output.
    """

    _REDACTED_KEYS = frozenset(
        {
            "password",
            "password_hash",
            "api_key",
            "gemini_api_key",
            "jwt_secret",
            "access_token",
            "refresh_token",
            "authorization",
            "secret",
            "token",
        }
    )

    def format(self, record: logging.LogRecord) -> str:  # noqa: A003
        correlation_id: str = getattr(record, "correlation_id", "-")
        base = (
            f"timestamp={self.formatTime(record, self.datefmt)} "
            f"level={record.levelname} "
            f"logger={record.name} "
            f"correlation_id={correlation_id} "
            f"message={record.getMessage()}"
        )
        # Append any extra structured fields attached to the record
        extras: dict[str, Any] = {
            k: ("***REDACTED***" if k.lower() in self._REDACTED_KEYS else v)
            for k, v in record.__dict__.items()
            if k
            not in {
                "args",
                "asctime",
                "created",
                "exc_info",
                "exc_text",
                "filename",
                "funcName",
                "levelname",
                "levelno",
                "lineno",
                "message",
                "module",
                "msecs",
                "msg",
                "name",
                "pathname",
                "process",
                "processName",
                "relativeCreated",
                "stack_info",
                "thread",
                "threadName",
                "correlation_id",
            }
        }
        if extras:
            extras_str = " ".join(f"{k}={v}" for k, v in extras.items())
            base = f"{base} {extras_str}"
        if record.exc_info:
            base = f"{base}\n{self.formatException(record.exc_info)}"
        return base


def configure_logging(log_level: str = "INFO") -> None:
    """
    Configure root and application loggers.

    Call once at application startup. Subsequent calls are safe (idempotent
    because the root logger handler list is replaced).
    """
    numeric_level = getattr(logging, log_level.upper(), logging.INFO)

    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(StructuredFormatter())

    root = logging.getLogger()
    root.handlers = [handler]
    root.setLevel(numeric_level)

    # Silence noisy third-party loggers in production
    for noisy in ("uvicorn.access", "motor", "pymongo", "chromadb"):
        logging.getLogger(noisy).setLevel(logging.WARNING)


def get_logger(name: str) -> logging.Logger:
    """Return a named logger for the given module or component."""
    return logging.getLogger(name)

