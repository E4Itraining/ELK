# ELK Upgrade Audit Tool - Docker Image
# ======================================
#
# Build:
#   docker build -t elk-upgrade-audit .
#
# Run:
#   docker run -it --rm elk-upgrade-audit interactive
#   docker run -it --rm -e ES_HOSTS="https://elasticsearch:9200" elk-upgrade-audit audit
#
# With config file:
#   docker run -it --rm -v ./config:/app/config elk-upgrade-audit audit

FROM python:3.11-slim-bookworm

LABEL maintainer="E4Itraining"
LABEL description="Outil d'audit et pilotage des upgrades ELK"
LABEL version="1.0.0"

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    APP_HOME=/app

# Create non-root user for security
RUN groupadd --gid 1000 elkaudit && \
    useradd --uid 1000 --gid elkaudit --shell /bin/bash --create-home elkaudit

WORKDIR ${APP_HOME}

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && apt-get clean

# Copy requirements first for better caching
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY --chown=elkaudit:elkaudit . .

# Create directories for reports and logs
RUN mkdir -p /app/reports /app/logs /app/config \
    && chown -R elkaudit:elkaudit /app

# Make scripts executable
RUN chmod +x /app/elk_upgrade_audit.py && \
    chmod +x /app/docker-entrypoint.sh

# Switch to non-root user
USER elkaudit

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python -c "import elasticsearch; print('OK')" || exit 1

# Default environment variables
ENV ES_HOSTS="https://localhost:9200" \
    ES_USERNAME="elastic" \
    ES_PASSWORD="" \
    ES_VERIFY_CERTS="true" \
    ES_CA_CERTS="" \
    TARGET_VERSION="8.11.0" \
    UPGRADE_STRATEGY="rolling" \
    REPORT_FORMAT="html" \
    LOG_LEVEL="INFO"

# Volume for reports and custom config
VOLUME ["/app/reports", "/app/config"]

# Entrypoint and default command
# Option 1: Direct Python execution (simpler)
ENTRYPOINT ["python", "/app/elk_upgrade_audit.py"]
CMD ["interactive"]

# Option 2: Use shell entrypoint (advanced features)
# Uncomment these lines and comment the ones above to use the shell entrypoint
# ENTRYPOINT ["/app/docker-entrypoint.sh"]
# CMD ["interactive"]
