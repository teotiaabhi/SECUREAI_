# === Stage 1: Builder ===
FROM python:3.12-slim AS builder

WORKDIR /build

# Install build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc libpq-dev git && \
    rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir --prefix=/install -r requirements.txt

# === Stage 2: Runtime ===
FROM python:3.12-slim AS runtime

# Security: create non-root user
RUN groupadd -r appuser && useradd -r -g appuser -d /app -s /sbin/nologin appuser

# Install runtime dependencies only (tini for PID 1 signal forwarding)
RUN apt-get update && apt-get install -y --no-install-recommends \
    libpq5 git curl tini && \
    rm -rf /var/lib/apt/lists/*

# Copy installed packages from builder
COPY --from=builder /install /usr/local

WORKDIR /app

# Copy application code
COPY --chown=appuser:appuser . .

# Clean up non-runtime files from the copied source
RUN find /app -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null; \
    find /app -name '*.pyc' -delete 2>/dev/null; \
    rm -rf /app/.git /app/.env* 2>/dev/null; \
    true

# Set permissions: app code read-only, temp dirs writable
RUN chmod -R 555 /app && \
    chmod +x /app/scripts/entrypoint.sh && \
    mkdir -p /app/tmp && chmod 700 /app/tmp && chown appuser:appuser /app/tmp && \
    mkdir -p /app/logs && chmod 700 /app/logs && chown appuser:appuser /app/logs

# Environment
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    SCAN_TEMP_DIR=/app/tmp

# Switch to non-root user
USER appuser

# Health check (readiness probe)
HEALTHCHECK --interval=30s --timeout=10s --start-period=30s --retries=3 \
    CMD curl -f http://localhost:8000/health/ready || exit 1

EXPOSE 8000

# tini as PID 1 for proper SIGTERM forwarding
# entrypoint.sh runs migrations, then exec's into uvicorn
ENTRYPOINT ["tini", "--", "/app/scripts/entrypoint.sh"]
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "1", "--log-level", "info", "--timeout-keep-alive", "30", "--timeout-graceful-shutdown", "30"]
