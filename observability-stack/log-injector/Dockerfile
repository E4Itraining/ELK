# ============================================================================
# LOG INJECTOR DOCKERFILE
# ============================================================================
# Python log injector for Elasticsearch and Kafka
# Supports multi-host configuration, topic routing, and log enrichment
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
    ES_CA_CERTS=""

# Kafka Connection
ENV KAFKA_BOOTSTRAP_SERVERS="kafka01:9092,kafka02:9092,kafka03:9092"

# Injection Settings
ENV INJECTION_RATE="10" \
    BATCH_SIZE="100" \
    INDEX_PREFIX="logs" \
    INJECTION_TARGET="elasticsearch"

# Configuration File
ENV CONFIG_FILE=""

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=10s --retries=3 \
    CMD python -c "import sys; sys.exit(0)"

# Run the injector (continuous by default)
ENTRYPOINT ["python", "-u", "log_injector.py"]
