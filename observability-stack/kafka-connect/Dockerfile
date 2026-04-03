# ============================================================================
# KAFKA CONNECT WITH PLUGINS DOCKERFILE
# ============================================================================

ARG CONFLUENT_VERSION=7.5.0
FROM confluentinc/cp-kafka-connect:${CONFLUENT_VERSION}

# Install connector plugins using confluent-hub
RUN confluent-hub install --no-prompt confluentinc/kafka-connect-elasticsearch:14.0.12 && \
    confluent-hub install --no-prompt confluentinc/kafka-connect-s3:10.5.7 && \
    confluent-hub install --no-prompt confluentinc/kafka-connect-jdbc:10.7.4 && \
    confluent-hub install --no-prompt confluentinc/kafka-connect-avro-converter:7.5.0 && \
    confluent-hub install --no-prompt debezium/debezium-connector-postgresql:2.4.0 && \
    confluent-hub install --no-prompt debezium/debezium-connector-mysql:2.4.0 && \
    confluent-hub install --no-prompt jcustenborder/kafka-connect-transform-common:0.1.0.58 && \
    confluent-hub install --no-prompt confluentinc/connect-transforms:1.4.4

# Copy custom configuration
COPY connect-distributed.properties /etc/kafka-connect/connect-distributed.properties

# Create connectors directory
RUN mkdir -p /etc/kafka-connect/connectors

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=120s --retries=5 \
    CMD curl -sf http://localhost:8083/connectors || exit 1

# Expose REST API port
EXPOSE 8083

# Default command
CMD ["/etc/confluent/docker/run"]
