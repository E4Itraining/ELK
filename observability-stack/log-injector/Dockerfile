# ============================================================================
# LOG INJECTOR DOCKERFILE
# ============================================================================
# Multi-stage build for a lightweight Python log injector
# ============================================================================

FROM python:3.11-slim as builder

WORKDIR /app

# Install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir --user -r requirements.txt

# ============================================================================
# FINAL IMAGE
# ============================================================================
FROM python:3.11-slim

WORKDIR /app

# Copy installed packages from builder
COPY --from=builder /root/.local /root/.local

# Make sure scripts in .local are usable
ENV PATH=/root/.local/bin:$PATH

# Copy application
COPY log_injector.py .

# Create non-root user
RUN useradd -m -u 1000 appuser && \
    chown -R appuser:appuser /app

USER appuser

# Environment variables with defaults
ENV ES_HOST=https://es01:9200 \
    ES_USER=elastic \
    ES_PASSWORD=changeme \
    ES_VERIFY_CERTS=false \
    INJECTION_RATE=10 \
    INDEX_PREFIX=logs

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=10s --retries=3 \
    CMD python -c "import sys; sys.exit(0)"

# Run the injector
ENTRYPOINT ["python", "-u", "log_injector.py"]
