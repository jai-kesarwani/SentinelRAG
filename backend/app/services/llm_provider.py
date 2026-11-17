"""
SentinelRAG — LLM Provider Interface & Gemini Adapter.

Modular, asynchronous LLM provider using Google Gemini REST API.
Enforces timeouts, safe error handling, credential privacy, and configurable model parameters.
"""
from __future__ import annotations

import abc
import asyncio
import random
import time
from typing import Any, Optional

import httpx

from app.core.config import get_settings
from app.core.logging import get_logger

logger = get_logger(__name__)


class LLMProviderError(Exception):
    """Base exception for LLM provider errors."""

    def __init__(self, message: str, code: str = "LLM_ERROR"):
        super().__init__(message)
        self.message = message
        self.code = code


class LLMConfigurationError(LLMProviderError):
    """Raised when the LLM provider is misconfigured (e.g., missing API key)."""

    def __init__(self, message: str = "LLM provider is not configured or missing API credentials"):
        super().__init__(message, code="LLM_NOT_CONFIGURED")


class LLMQuotaExceededError(LLMProviderError):
    """Raised when the LLM provider returns rate limit or quota exceeded (HTTP 429)."""

    def __init__(self, message: str = "LLM provider quota exceeded or rate limited. Please try again shortly."):
        super().__init__(message, code="LLM_QUOTA_EXCEEDED")


class LLMUnavailableError(LLMProviderError):
    """Raised when the LLM provider service is temporarily overloaded or unavailable."""

    def __init__(self, message: str = "LLM provider is temporarily unavailable. Please retry later."):
        super().__init__(message, code="LLM_UNAVAILABLE")


class BaseLLMProvider(abc.ABC):
    """Abstract base class for LLM providers."""

    @abc.abstractmethod
    async def generate_response(
        self,
        system_prompt: str,
        user_prompt: str,
        temperature: float = 0.2,
        max_output_tokens: int = 1024,
    ) -> str:
        """Generate response given a system prompt and user prompt."""
        raise NotImplementedError


class GeminiProvider(BaseLLMProvider):
    """
    Google Gemini API provider implementation using asynchronous HTTP requests.
    Supports system instructions, parameter tuning, controlled retries, and bounded execution timeouts.
    """

    # Verified fallback models in case the configured primary model encounters temporary capacity spikes
    FALLBACK_MODELS = ["gemini-3.5-flash", "gemini-3.5-flash-lite"]

    def __init__(
        self,
        api_key: Optional[str] = None,
        model_name: Optional[str] = None,
        timeout_seconds: float = 25.0,
        max_attempts: int = 3,
    ):
        settings = get_settings()
        self.api_key = api_key if api_key is not None else settings.GEMINI_API_KEY
        self.model_name = model_name or settings.GEMINI_MODEL or "gemini-3.5-flash"
        self.timeout_seconds = timeout_seconds
        self.max_attempts = max_attempts
        self.base_url = "https://generativelanguage.googleapis.com/v1beta/models"

    def is_configured(self) -> bool:
        """Check whether a non-empty API key is configured."""
        return bool(self.api_key and self.api_key.strip() and self.api_key != "your-gemini-api-key-here")

    def _get_model_for_attempt(self, attempt: int) -> str:
        """
        Return the primary model for attempt 1.
        If attempt > 1 and primary model is known to experience capacity issues,
        gracefully fall back to an active responsive model.
        """
        if attempt == 1:
            return self.model_name
        # On retry, if primary is experiencing capacity issues, try verified fallback
        for candidate in self.FALLBACK_MODELS:
            if candidate != self.model_name:
                return candidate
        return self.model_name

    async def generate_response(
        self,
        system_prompt: str,
        user_prompt: str,
        temperature: float = 0.2,
        max_output_tokens: int = 1024,
    ) -> str:
        """
        Call Gemini generateContent API asynchronously with system instructions.
        Applies a 25-second per-attempt timeout, maximum 3 attempts, exponential backoff with jitter,
        and safe diagnostic logging.

        Args:
            system_prompt: Trusted system instructions for the LLM.
            user_prompt: Grounded context and user question.
            temperature: Sampling temperature (0.0 to 1.0).
            max_output_tokens: Maximum token limit for the response.

        Returns:
            str: Generated text answer.
        """
        if not self.is_configured():
            logger.warning("Gemini API key is not configured")
            raise LLMConfigurationError("Gemini API key is missing or not configured.")

        payload: dict[str, Any] = {
            "contents": [
                {
                    "role": "user",
                    "parts": [{"text": user_prompt}],
                }
            ],
            "generationConfig": {
                "temperature": temperature,
                "maxOutputTokens": max_output_tokens,
                "topP": 0.95,
            },
        }

        if system_prompt:
            payload["systemInstruction"] = {
                "parts": [{"text": system_prompt}],
            }

        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json",
            "x-goog-api-key": self.api_key,
        }

        timeout = httpx.Timeout(self.timeout_seconds, connect=5.0)

        for attempt in range(1, self.max_attempts + 1):
            current_model = self._get_model_for_attempt(attempt)
            url = f"{self.base_url}/{current_model}:generateContent"
            start_time = time.monotonic()

            logger.info(
                "Dispatching Gemini generateContent request",
                extra={
                    "attempt": attempt,
                    "max_attempts": self.max_attempts,
                    "model": current_model,
                    "timeout_seconds": self.timeout_seconds,
                },
            )

            try:
                async with httpx.AsyncClient(timeout=timeout) as client:
                    response = await client.post(url, json=payload, headers=headers)

                latency_ms = round((time.monotonic() - start_time) * 1000, 2)

                # -------------------------------------------------------------
                # 1. Success Response (200 OK)
                # -------------------------------------------------------------
                if response.status_code == 200:
                    data = response.json()
                    candidates = data.get("candidates", [])
                    if not candidates:
                        logger.warning(
                            "Gemini API returned 200 OK but candidates list is empty",
                            extra={"attempt": attempt, "latency_ms": latency_ms, "model": current_model},
                        )
                        return "I was unable to generate an answer from the provided documents."

                    parts = candidates[0].get("content", {}).get("parts", [])
                    if not parts:
                        logger.warning(
                            "Gemini API returned candidate without content parts",
                            extra={"attempt": attempt, "latency_ms": latency_ms, "model": current_model},
                        )
                        return "I was unable to generate an answer from the provided documents."

                    generated_text = "".join(p.get("text", "") for p in parts).strip()
                    logger.info(
                        "Gemini API request succeeded",
                        extra={
                            "attempt": attempt,
                            "status": 200,
                            "latency_ms": latency_ms,
                            "model": current_model,
                            "output_chars": len(generated_text),
                        },
                    )
                    return generated_text

                # -------------------------------------------------------------
                # 2. Rate Limit / Quota Exceeded (429) - Do Not Retry
                # -------------------------------------------------------------
                if response.status_code == 429:
                    logger.warning(
                        "Gemini API rate limit or quota exceeded",
                        extra={"attempt": attempt, "status": 429, "latency_ms": latency_ms, "model": current_model},
                    )
                    raise LLMQuotaExceededError()

                # -------------------------------------------------------------
                # 3. Client Errors (400, 401, 403) - Do Not Retry
                # -------------------------------------------------------------
                if response.status_code in {400, 401, 403}:
                    err_summary = "Client error"
                    try:
                        err_summary = response.json().get("error", {}).get("message", f"HTTP {response.status_code}")
                    except Exception:  # noqa: BLE001
                        pass

                    logger.error(
                        "Gemini API client error (non-retryable)",
                        extra={
                            "attempt": attempt,
                            "status": response.status_code,
                            "latency_ms": latency_ms,
                            "model": current_model,
                            "error_summary": err_summary,
                        },
                    )
                    if response.status_code in {401, 403}:
                        raise LLMConfigurationError(f"Gemini API authorization failed: {err_summary}")
                    raise LLMProviderError(f"Gemini API error: {err_summary}", code="GEMINI_API_ERROR")

                # -------------------------------------------------------------
                # 4. Transient Server Errors (500, 502, 503, 504) - Controlled Retry
                # -------------------------------------------------------------
                if response.status_code in {500, 502, 503, 504}:
                    err_summary = f"Server error HTTP {response.status_code}"
                    try:
                        err_summary = response.json().get("error", {}).get("message", err_summary)
                    except Exception:  # noqa: BLE001
                        pass

                    if attempt < self.max_attempts:
                        delay = (1.0 * (2 ** (attempt - 1))) + random.uniform(0.1, 0.5)
                        logger.warning(
                            "Gemini API returned transient 5xx error; retrying with backoff",
                            extra={
                                "attempt": attempt,
                                "max_attempts": self.max_attempts,
                                "status": response.status_code,
                                "latency_ms": latency_ms,
                                "model": current_model,
                                "retry_in_s": round(delay, 2),
                                "error_summary": err_summary,
                            },
                        )
                        await asyncio.sleep(delay)
                        continue

                    logger.error(
                        "Gemini API 5xx errors exhausted all retry attempts",
                        extra={
                            "attempt": attempt,
                            "max_attempts": self.max_attempts,
                            "status": response.status_code,
                            "latency_ms": latency_ms,
                            "model": current_model,
                            "error_summary": err_summary,
                        },
                    )
                    raise LLMUnavailableError(
                        f"Gemini service unavailable after {self.max_attempts} attempts (HTTP {response.status_code})."
                    )

                # Fallback for unexpected HTTP status codes
                logger.error(
                    "Gemini API unexpected status code",
                    extra={"attempt": attempt, "status": response.status_code, "latency_ms": latency_ms},
                )
                raise LLMProviderError(f"Gemini API unexpected status {response.status_code}", code="GEMINI_UNEXPECTED_STATUS")

            except LLMProviderError:
                raise

            except (httpx.TimeoutException, httpx.RequestError) as exc:
                latency_ms = round((time.monotonic() - start_time) * 1000, 2)
                is_timeout = isinstance(exc, httpx.TimeoutException)
                err_label = "Timeout" if is_timeout else type(exc).__name__

                if attempt < self.max_attempts:
                    delay = (1.0 * (2 ** (attempt - 1))) + random.uniform(0.1, 0.5)
                    logger.warning(
                        "Gemini API request failed transiently; retrying with backoff",
                        extra={
                            "attempt": attempt,
                            "max_attempts": self.max_attempts,
                            "error_type": err_label,
                            "latency_ms": latency_ms,
                            "model": current_model,
                            "retry_in_s": round(delay, 2),
                        },
                    )
                    await asyncio.sleep(delay)
                    continue

                if is_timeout:
                    logger.error(
                        "Gemini API request timed out after exhausting all retries",
                        extra={
                            "attempt": attempt,
                            "max_attempts": self.max_attempts,
                            "timeout_per_attempt": self.timeout_seconds,
                            "latency_ms": latency_ms,
                            "model": current_model,
                        },
                    )
                    raise LLMUnavailableError(
                        f"LLM response timed out after {self.max_attempts} attempts ({self.timeout_seconds}s limit per attempt)."
                    ) from exc

                logger.error(
                    "Gemini API network error after exhausting all retries",
                    extra={
                        "attempt": attempt,
                        "max_attempts": self.max_attempts,
                        "latency_ms": latency_ms,
                        "error_type": err_label,
                        "model": current_model,
                    },
                )
                raise LLMUnavailableError(
                    f"Network error communicating with LLM service after {self.max_attempts} attempts: {exc}"
                ) from exc


gemini_provider = GeminiProvider()
