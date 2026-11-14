# syntax=docker/dockerfile:1
FROM python:3.12-slim AS base

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /app

# Install git and minimal system tools required for repository cloning
RUN apt-get update && apt-get install -y --no-install-recommends \
    git \
    ca-certificates \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Create non-root service user
RUN groupadd -r bountysweep && useradd -r -g bountysweep -d /app -s /sbin/nologin bountysweep

COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt

COPY config /app/config
COPY discovery /app/discovery
COPY evaluator /app/evaluator
COPY sandbox /app/sandbox
COPY payouts /app/payouts
COPY notifications /app/notifications
COPY api /app/api

RUN chown -R bountysweep:bountysweep /app

USER bountysweep

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD curl -f http://localhost:8000/health || exit 1

CMD ["uvicorn", "api.main:app", "--host", "0.0.0.0", "--port", "8000"]
