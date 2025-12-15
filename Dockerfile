# ============================================================================
# LOG INJECTOR DOCKERFILE
# ============================================================================
# Lightweight Python log injector for Elasticsearch
# ============================================================================

FROM python:3.11-slim

WORKDIR /app

# Create non-root user first
RUN useradd -m -u 1000 appuser

# Install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application
COPY --chown=appuser:appuser log_injector.py .

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
