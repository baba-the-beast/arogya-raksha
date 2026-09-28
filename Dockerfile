# ==============================================================================
# Stage 1: Builder
# ==============================================================================
FROM python:3.12-slim AS builder

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /build

RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    build-essential \
    libpq-dev \
    && rm -rf /var/lib/apt/lists/*

RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# ==============================================================================
# Stage 2: Hardened Runtime
# ==============================================================================
FROM python:3.12-slim AS runner

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PATH="/opt/venv/bin:$PATH" \
    PORT=5000

# Install runtime dependencies (libpq5 for PostgreSQL, curl for healthchecks)
RUN apt-get update && apt-get install -y --no-install-recommends \
    libpq5 \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Create dedicated non-root system group & user: arogya (UID 10001)
RUN groupadd -g 10001 arogya && \
    useradd -u 10001 -g arogya -s /bin/sh -d /app arogya

WORKDIR /app

# Copy isolated virtual environment from builder stage
COPY --from=builder --chown=arogya:arogya /opt/venv /opt/venv

# Copy application source code
COPY --chown=arogya:arogya . /app

# Ensure runtime directories exist with non-root ownership
RUN mkdir -p /app/backups /app/data && \
    chown -R arogya:arogya /app

# Drop root privileges
USER arogya

EXPOSE 5000

# Container health monitoring via /healthz endpoint
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD curl -f http://127.0.0.1:5000/healthz || exit 1

# WSGI Application Server Execution:
# ARCHITECTURAL NOTE: Sync workers (-w 4) are strictly mandatory.
# Asynchronous workers (gevent / eventlet) monkey-patch socket and threading primitives,
# corrupting PyCryptodome / cryptography C extensions and cryptographic PRNG entropy pools.
CMD ["gunicorn", "-w", "4", "-b", "0.0.0.0:5000", "app:create_app()"]
