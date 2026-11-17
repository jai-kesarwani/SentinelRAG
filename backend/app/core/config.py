"""
SentinelRAG — Application Configuration.

Reads all settings from environment variables using pydantic-settings.
Never commit a .env file containing real secrets.
"""
from __future__ import annotations

from functools import lru_cache

from pydantic import field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Central application configuration loaded from environment variables."""

    model_config = SettingsConfigDict(
        env_file="../.env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # ------------------------------------------------------------------ #
    # Application
    # ------------------------------------------------------------------ #
    APP_ENV: str = "development"
    APP_HOST: str = "0.0.0.0"
    APP_PORT: int = 8000
    APP_VERSION: str = "0.1.0"
    APP_NAME: str = "SentinelRAG API"

    # ------------------------------------------------------------------ #
    # MongoDB
    # ------------------------------------------------------------------ #
    MONGODB_URI: str = "mongodb://localhost:27017"
    MONGODB_DATABASE: str = "sentinelrag"

    # ------------------------------------------------------------------ #
    # ChromaDB (vector store)
    # ------------------------------------------------------------------ #
    CHROMA_PERSIST_DIR: str = "./chroma_data"
    CHROMA_COLLECTION_NAME: str = "sentinelrag_chunks"

    # ------------------------------------------------------------------ #
    # Gemini API (placeholder — activated in Phase 4)
    # ------------------------------------------------------------------ #
    GEMINI_API_KEY: str = ""
    GEMINI_MODEL: str = "gemini-3.5-flash"

    # ------------------------------------------------------------------ #
    # JWT & Session Authentication
    # ------------------------------------------------------------------ #
    JWT_SECRET: str = "change-me-in-production-use-a-strong-secret-key-32b"
    JWT_ALGORITHM: str = "HS256"
    JWT_ISSUER: str = "sentinelrag"
    JWT_AUDIENCE: str = "sentinelrag-client"
    ACCESS_TOKEN_TTL_MINUTES: int = 30
    REFRESH_TOKEN_TTL_DAYS: int = 7
    REFRESH_COOKIE_NAME: str = "sentinel_refresh"
    REFRESH_COOKIE_SECURE: bool = False  # Set to True in HTTPS production
    REFRESH_COOKIE_SAMESITE: str = "lax"  # lax | strict | none

    # ------------------------------------------------------------------ #
    # CORS
    # ------------------------------------------------------------------ #
    CORS_ORIGINS: list[str] = ["http://localhost:5173"]

    # ------------------------------------------------------------------ #
    # Logging
    # ------------------------------------------------------------------ #
    LOG_LEVEL: str = "INFO"

    # ------------------------------------------------------------------ #
    # File uploads & Document Ingestion (Phase 3)
    # ------------------------------------------------------------------ #
    UPLOAD_DIR: str = "./uploads"
    MAX_UPLOAD_MB: int = 20
    CHUNK_SIZE_TOKENS: int = 800
    CHUNK_OVERLAP_TOKENS: int = 150

    # ------------------------------------------------------------------ #
    # Validators
    # ------------------------------------------------------------------ #
    @field_validator("LOG_LEVEL")
    @classmethod
    def validate_log_level(cls, v: str) -> str:
        allowed = {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}
        upper = v.upper()
        if upper not in allowed:
            raise ValueError(f"LOG_LEVEL must be one of {allowed}")
        return upper

    @field_validator("APP_ENV")
    @classmethod
    def validate_app_env(cls, v: str) -> str:
        allowed = {"development", "staging", "production", "test"}
        lower = v.lower()
        if lower not in allowed:
            raise ValueError(f"APP_ENV must be one of {allowed}")
        return lower

    @property
    def is_production(self) -> bool:
        return self.APP_ENV == "production"

    @property
    def is_development(self) -> bool:
        return self.APP_ENV == "development"


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Return the cached application settings singleton."""
    return Settings()

