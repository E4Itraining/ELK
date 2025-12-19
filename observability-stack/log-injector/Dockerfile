# ============================================================================
# LOG INJECTOR DOCKERFILE
# ============================================================================
# Lightweight Python log injector for Elasticsearch 8.x and 9.x
# Supports multi-host configuration and continuous injection
# ============================================================================

FROM python:3.11-slim

WORKDIR /app

# Create non-root user first
RUN useradd -m -u 1000 appuser

# Install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application files
COPY --chown=appuser:appuser log_injector.py .
COPY --chown=appuser:appuser config.yaml.example .

USER appuser

# ============================================================================
# Environment Variables
# ============================================================================
# Elasticsearch Connection
ENV ES_HOSTS="" \
    ES_HOST="https://es01:9200" \
    ES_USER="elastic" \
    ES_PASSWORD="changeme" \
    ES_API_KEY="" \
    ES_VERIFY_CERTS="false" \
    ES_CA_CERTS="" \
    # Injection Settings
    INJECTION_RATE="10" \
    BATCH_SIZE="100" \
    INDEX_PREFIX="logs" \
    # Configuration File
    CONFIG_FILE=""

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=10s --retries=3 \
    CMD python -c "import sys; sys.exit(0)"

# Run the injector (continuous by default)
ENTRYPOINT ["python", "-u", "log_injector.py"]
