"""
SentinelRAG — FastAPI Application Entry Point.

Architecture:
  - Modular monolith: single FastAPI app, independent service modules.
  - All routes versioned under /api/v1.
  - Standard response envelope: {"data": {...}, "meta": {"correlation_id": "..."}}.
  - Standard error envelope:  {"error": {"code": "...", "message": "...", "correlation_id": "..."}}.

Security principles applied here:
  - CORS is configured from settings; never wildcard in production.
  - Correlation IDs are generated server-side; client values are ignored.
  - Stack traces and internal paths are never returned to clients.
"""
from __future__ import annotations

import logging
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from typing import AsyncGenerator

from fastapi import FastAPI, HTTPException, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from app.api.routes.auth import router as auth_router
from app.api.routes.chat import router as chat_router
from app.api.routes.documents import router as documents_router
from app.api.routes.health import router as health_router
from app.api.routes.security_analytics import router as security_analytics_router
from app.api.routes.simulator import router as simulator_router
from app.core.config import get_settings
from app.core.logging import configure_logging, get_logger
from app.db.chromadb import chromadb_manager
from app.db.conversations_repo import conversations_repo
from app.db.documents_repo import documents_repo
from app.db.mongodb import mongodb_manager
from app.db.security_analytics_repo import security_analytics_repo
from app.db.security_events_repo import security_events_repo
from app.db.simulation_repo import simulation_repo
from app.db.users_repo import users_repo
from app.utils.correlation import CorrelationIDMiddleware, get_correlation_id
from app.utils.security_headers import SecurityHeadersMiddleware

# Configure logging before anything else logs
settings = get_settings()
configure_logging(settings.LOG_LEVEL)
logger = get_logger(__name__)


# --------------------------------------------------------------------------- #
# Lifespan (startup / shutdown)
# --------------------------------------------------------------------------- #

@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    """Handle application startup and graceful shutdown."""
    # ---- Startup ----
    logger.info(
        "SentinelRAG API starting",
        extra={
            "version": settings.APP_VERSION,
            "environment": settings.APP_ENV,
        },
    )

    # Connect to MongoDB (may raise on hard failure; logged below)
    try:
        await mongodb_manager.connect()
        # Initialize users, documents, conversations & security_events indexes
        await users_repo.init_indexes()
        await documents_repo.init_indexes()
        await conversations_repo.init_indexes()
        await security_events_repo.init_indexes()
        await security_analytics_repo.init_indexes()
        await simulation_repo.init_indexes()
    except Exception as exc:  # noqa: BLE001
        logger.error(
            "MongoDB connection failed at startup — health endpoint will report unhealthy",
            extra={"error": str(exc)},
        )

    # Initialize ChromaDB (synchronous; persistent client)
    try:
        chromadb_manager.initialize()
    except Exception as exc:  # noqa: BLE001
        logger.error(
            "ChromaDB initialization failed at startup — health endpoint will report unhealthy",
            extra={"error": str(exc)},
        )

    logger.info("SentinelRAG API startup complete")
    yield

    # ---- Shutdown ----
    logger.info("SentinelRAG API shutting down")
    await mongodb_manager.disconnect()
    logger.info("SentinelRAG API shutdown complete")


# --------------------------------------------------------------------------- #
# Application factory
# --------------------------------------------------------------------------- #

def create_app() -> FastAPI:
    """Create and configure the FastAPI application."""
    _settings = get_settings()

    app = FastAPI(
        title=_settings.APP_NAME,
        version=_settings.APP_VERSION,
        description=(
            "SentinelRAG — Secure Retrieval-Augmented Generation Agent. "
            "API documentation for backend services."
        ),
        docs_url="/api/docs",
        redoc_url="/api/redoc",
        openapi_url="/api/openapi.json",
        lifespan=lifespan,
    )

    # ------------------------------------------------------------------ #
    # Middleware (order matters: added last = runs first)
    # ------------------------------------------------------------------ #

    # 1. CORS — must be before CorrelationIDMiddleware so preflight requests
    #    are handled before our middleware adds IDs.
    app.add_middleware(
        CORSMiddleware,
        allow_origins=_settings.CORS_ORIGINS,
        allow_credentials=True,
        allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
        allow_headers=["*"],
        expose_headers=["X-Correlation-ID"],
    )

    # 2. Correlation ID — attaches a UUID to every request
    app.add_middleware(CorrelationIDMiddleware)

    # 3. Security Headers — defense-in-depth HTTP security headers
    app.add_middleware(SecurityHeadersMiddleware)

    # ------------------------------------------------------------------ #
    # Global exception handlers
    # ------------------------------------------------------------------ #

    @app.exception_handler(HTTPException)
    async def http_exception_handler(request: Request, exc: HTTPException) -> JSONResponse:
        """Format HTTP exceptions into the standard error envelope."""
        correlation_id = get_correlation_id(request)
        if isinstance(exc.detail, dict):
            code = exc.detail.get("code", "HTTP_ERROR")
            message = exc.detail.get("message", "An error occurred")
        else:
            code = "HTTP_ERROR"
            message = str(exc.detail)
        return JSONResponse(
            status_code=exc.status_code,
            content={
                "error": {
                    "code": code,
                    "message": message,
                    "correlation_id": correlation_id,
                }
            },
            headers=exc.headers,
        )

    @app.exception_handler(Exception)
    async def global_exception_handler(request: Request, exc: Exception) -> JSONResponse:
        """
        Catch-all handler: returns a safe error envelope without leaking
        stack traces, internal paths, or secrets.
        """
        correlation_id = get_correlation_id(request)
        logger.error(
            "Unhandled exception",
            exc_info=exc,
            extra={"correlation_id": correlation_id, "path": request.url.path},
        )
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={
                "error": {
                    "code": "INTERNAL_SERVER_ERROR",
                    "message": "An unexpected error occurred. Please try again later.",
                    "correlation_id": correlation_id,
                }
            },
        )

    @app.exception_handler(404)
    async def not_found_handler(request: Request, exc: Exception) -> JSONResponse:
        correlation_id = get_correlation_id(request)
        return JSONResponse(
            status_code=status.HTTP_404_NOT_FOUND,
            content={
                "error": {
                    "code": "NOT_FOUND",
                    "message": "The requested resource was not found.",
                    "correlation_id": correlation_id,
                }
            },
        )

    @app.exception_handler(405)
    async def method_not_allowed_handler(request: Request, exc: Exception) -> JSONResponse:
        correlation_id = get_correlation_id(request)
        return JSONResponse(
            status_code=status.HTTP_405_METHOD_NOT_ALLOWED,
            content={
                "error": {
                    "code": "METHOD_NOT_ALLOWED",
                    "message": "Method not allowed.",
                    "correlation_id": correlation_id,
                }
            },
        )

    # ------------------------------------------------------------------ #
    # Routes
    # ------------------------------------------------------------------ #

    # Quick liveness ping (no DB dependency)
    @app.get("/api/v1/ping", tags=["Health"], summary="Quick liveness ping")
    async def ping(request: Request) -> dict:
        return {
            "data": {
                "pong": True,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            },
            "meta": {"correlation_id": get_correlation_id(request)},
        }

    # Health check routes: /api/v1/health, /api/v1/health/database, /api/v1/health/vector-store
    app.include_router(health_router, prefix="/api/v1")
    # Authentication routes: /api/v1/auth/register, login, refresh, logout, me
    app.include_router(auth_router, prefix="/api/v1")
    # Documents routes: /api/v1/documents/upload, list, get, delete
    app.include_router(documents_router, prefix="/api/v1")
    # Chat & RAG routes: /api/v1/chat/conversations, messages
    app.include_router(chat_router, prefix="/api/v1")
    # Attack Simulator routes: /api/v1/simulator/scenarios, runs, stats
    app.include_router(simulator_router, prefix="/api/v1")
    # Security Center & Analytics routes: /api/v1/security-center/...
    app.include_router(security_analytics_router, prefix="/api/v1")

    return app


# --------------------------------------------------------------------------- #
# Application instance (used by uvicorn)
# --------------------------------------------------------------------------- #

app = create_app()


# --------------------------------------------------------------------------- #
# Development entry point
# --------------------------------------------------------------------------- #

if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        "app.main:app",
        host=settings.APP_HOST,
        port=settings.APP_PORT,
        reload=settings.is_development,
        log_level=settings.LOG_LEVEL.lower(),
    )

