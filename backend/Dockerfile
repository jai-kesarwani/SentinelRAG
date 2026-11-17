# =============================================================================
# SentinelRAG Backend Dockerfile
# Python 3.12 Slim | Production ASGI Application
# =============================================================================

FROM python:3.12-slim AS base

# Prevent Python from writing .pyc files and enable unbuffered logging
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    DEBIAN_FRONTEND=noninteractive

# Install curl for container health check and minimal system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Create non-root system user and group for container security
RUN groupadd -g 10001 appgroup && \
    useradd -u 10001 -g appgroup -s /bin/bash -m appuser

# Install Python dependencies first for optimal Docker layer caching
COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# Copy application source code
COPY app /app/app

# Create persistent storage directories and assign ownership to non-root appuser
RUN mkdir -p /app/uploads /app/chroma_data && \
    chown -R appuser:appgroup /app

# Switch to unprivileged non-root user
USER appuser

# Expose FastAPI application port
EXPOSE 8000

# Docker healthcheck using the built-in SentinelRAG health endpoint
HEALTHCHECK --interval=20s --timeout=5s --start-period=15s --retries=3 \
    CMD curl -f http://localhost:8000/api/v1/health || exit 1

# Production ASGI server command with forwarded proxy headers support
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--proxy-headers", "--forwarded-allow-ips", "*"]

