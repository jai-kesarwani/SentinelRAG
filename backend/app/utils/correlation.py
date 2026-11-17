"""
SentinelRAG — Correlation ID Middleware.

Every HTTP request receives a unique UUID4 correlation ID.
The ID is stored on request.state and returned in the X-Correlation-ID header
so distributed traces can be correlated across logs and responses.
"""
from __future__ import annotations

import uuid

from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.types import ASGIApp


class CorrelationIDMiddleware(BaseHTTPMiddleware):
    """Attach a correlation ID to every request and response."""

    HEADER_NAME = "X-Correlation-ID"

    def __init__(self, app: ASGIApp) -> None:
        super().__init__(app)

    async def dispatch(
        self, request: Request, call_next: RequestResponseEndpoint
    ) -> Response:
        # Accept a client-supplied correlation ID or generate a fresh one.
        # We always generate a new server-side ID to prevent injection of
        # arbitrary values into log correlation chains.
        correlation_id = str(uuid.uuid4())
        request.state.correlation_id = correlation_id

        response: Response = await call_next(request)
        response.headers[self.HEADER_NAME] = correlation_id
        return response


def get_correlation_id(request: Request) -> str:
    """
    Retrieve the correlation ID attached to this request.

    Returns a fallback string if the middleware was not applied.
    """
    return getattr(request.state, "correlation_id", "no-correlation-id")

