#!/bin/bash
# ============================================================================
# KAFKA TOPIC INITIALIZATION SCRIPT
# ============================================================================
# Creates and configures topics with optimized settings
# ============================================================================

set -e

# Wait for Kafka to be ready
echo "Waiting for Kafka cluster to be ready..."
KAFKA_READY=false
for i in {1..60}; do
    if kafka-broker-api-versions --bootstrap-server kafka01:9092 >/dev/null 2>&1; then
        KAFKA_READY=true
        break
    fi
    echo "Waiting for Kafka... ($i/60)"
    sleep 5
done

if [ "$KAFKA_READY" != "true" ]; then
    echo "ERROR: Kafka cluster not ready after 5 minutes"
    exit 1
fi

echo "Kafka cluster is ready!"

# ============================================================================
# TOPIC CONFIGURATIONS
# ============================================================================

# Function to create topic with config
create_topic() {
    local TOPIC_NAME=$1
    local PARTITIONS=$2
    local REPLICATION=$3
    shift 3
    local CONFIGS="$@"

    echo "Creating topic: ${TOPIC_NAME}"

    # Check if topic exists
    if kafka-topics --bootstrap-server kafka01:9092 --list | grep -q "^${TOPIC_NAME}$"; then
        echo "  Topic ${TOPIC_NAME} already exists, updating config..."
        # Update config
        if [ -n "$CONFIGS" ]; then
            kafka-configs --bootstrap-server kafka01:9092 \
                --entity-type topics --entity-name ${TOPIC_NAME} \
                --alter ${CONFIGS}
        fi
    else
        # Create new topic
        kafka-topics --bootstrap-server kafka01:9092 \
            --create --topic ${TOPIC_NAME} \
            --partitions ${PARTITIONS} \
            --replication-factor ${REPLICATION} \
            ${CONFIGS}
    fi
    echo "  Done: ${TOPIC_NAME}"
}

# ============================================================================
# MAIN TOPICS
# ============================================================================
echo ""
echo "Creating main topics..."

# Main logs topic - high throughput
create_topic "logs" 6 3 \
    --config retention.ms=604800000 \
    --config retention.bytes=10737418240 \
    --config segment.bytes=1073741824 \
    --config cleanup.policy=delete \
    --config compression.type=lz4 \
    --config min.insync.replicas=2

# Metrics topic - medium retention
create_topic "metrics" 3 3 \
    --config retention.ms=259200000 \
    --config retention.bytes=5368709120 \
    --config segment.bytes=536870912 \
    --config cleanup.policy=delete \
    --config compression.type=snappy \
    --config min.insync.replicas=2

# Events topic - long retention
create_topic "events" 3 3 \
    --config retention.ms=2592000000 \
    --config retention.bytes=10737418240 \
    --config segment.bytes=1073741824 \
    --config cleanup.policy=delete \
    --config compression.type=gzip \
    --config min.insync.replicas=2

# ============================================================================
# LEVEL-BASED TOPICS
# ============================================================================
echo ""
echo "Creating level-based topics..."

create_topic "logs-errors" 3 3 \
    --config retention.ms=2592000000 \
    --config retention.bytes=10737418240 \
    --config cleanup.policy=delete \
    --config compression.type=gzip \
    --config min.insync.replicas=2

create_topic "logs-warnings" 3 3 \
    --config retention.ms=604800000 \
    --config retention.bytes=5368709120 \
    --config cleanup.policy=delete \
    --config compression.type=lz4 \
    --config min.insync.replicas=2

create_topic "logs-info" 6 3 \
    --config retention.ms=259200000 \
    --config retention.bytes=10737418240 \
    --config cleanup.policy=delete \
    --config compression.type=lz4 \
    --config min.insync.replicas=2

create_topic "logs-debug" 3 3 \
    --config retention.ms=86400000 \
    --config retention.bytes=2147483648 \
    --config cleanup.policy=delete \
    --config compression.type=snappy \
    --config min.insync.replicas=1

# ============================================================================
# ENVIRONMENT-BASED TOPICS
# ============================================================================
echo ""
echo "Creating environment-based topics..."

create_topic "logs-prod" 6 3 \
    --config retention.ms=2592000000 \
    --config retention.bytes=21474836480 \
    --config cleanup.policy=delete \
    --config compression.type=lz4 \
    --config min.insync.replicas=2

create_topic "logs-staging" 3 3 \
    --config retention.ms=604800000 \
    --config retention.bytes=5368709120 \
    --config cleanup.policy=delete \
    --config compression.type=lz4 \
    --config min.insync.replicas=2

create_topic "logs-dev" 1 2 \
    --config retention.ms=86400000 \
    --config retention.bytes=1073741824 \
    --config cleanup.policy=delete \
    --config compression.type=snappy \
    --config min.insync.replicas=1

# ============================================================================
# DEAD LETTER QUEUE TOPICS
# ============================================================================
echo ""
echo "Creating Dead Letter Queue topics..."

create_topic "dlq-logs" 3 3 \
    --config retention.ms=2592000000 \
    --config retention.bytes=10737418240 \
    --config cleanup.policy=delete \
    --config compression.type=gzip \
    --config min.insync.replicas=2

create_topic "dlq-metrics" 3 3 \
    --config retention.ms=2592000000 \
    --config retention.bytes=5368709120 \
    --config cleanup.policy=delete \
    --config compression.type=gzip \
    --config min.insync.replicas=2

create_topic "dlq-events" 3 3 \
    --config retention.ms=2592000000 \
    --config retention.bytes=5368709120 \
    --config cleanup.policy=delete \
    --config compression.type=gzip \
    --config min.insync.replicas=2

# ============================================================================
# SCHEMA REGISTRY INTERNAL TOPIC
# ============================================================================
echo ""
echo "Creating Schema Registry topic..."

create_topic "_schemas" 1 3 \
    --config cleanup.policy=compact \
    --config min.insync.replicas=2

# ============================================================================
# KAFKA CONNECT TOPICS
# ============================================================================
echo ""
echo "Creating Kafka Connect topics..."

create_topic "connect-configs" 1 3 \
    --config cleanup.policy=compact \
    --config min.insync.replicas=2

create_topic "connect-offsets" 25 3 \
    --config cleanup.policy=compact \
    --config min.insync.replicas=2

create_topic "connect-status" 5 3 \
    --config cleanup.policy=compact \
    --config min.insync.replicas=2

# ============================================================================
# KSQL INTERNAL TOPICS
# ============================================================================
echo ""
echo "Creating KSQL topics..."

create_topic "_confluent-ksql-default__command_topic" 1 3 \
    --config cleanup.policy=compact \
    --config min.insync.replicas=2

# ============================================================================
# LOG TYPE BASED TOPICS
# ============================================================================
echo ""
echo "Creating log-type based topics..."

create_topic "logs-application" 6 3 \
    --config retention.ms=604800000 \
    --config retention.bytes=10737418240 \
    --config cleanup.policy=delete \
    --config compression.type=lz4 \
    --config min.insync.replicas=2

create_topic "logs-access" 6 3 \
    --config retention.ms=604800000 \
    --config retention.bytes=10737418240 \
    --config cleanup.policy=delete \
    --config compression.type=lz4 \
    --config min.insync.replicas=2

create_topic "logs-metrics" 3 3 \
    --config retention.ms=259200000 \
    --config retention.bytes=5368709120 \
    --config cleanup.policy=delete \
    --config compression.type=snappy \
    --config min.insync.replicas=2

# ============================================================================
# AGGREGATION TOPICS FOR KSQL
# ============================================================================
echo ""
echo "Creating aggregation topics..."

create_topic "logs-aggregated-1m" 3 3 \
    --config retention.ms=604800000 \
    --config cleanup.policy=delete \
    --config compression.type=snappy \
    --config min.insync.replicas=2

create_topic "logs-aggregated-5m" 3 3 \
    --config retention.ms=2592000000 \
    --config cleanup.policy=delete \
    --config compression.type=snappy \
    --config min.insync.replicas=2

create_topic "alerts-stream" 3 3 \
    --config retention.ms=604800000 \
    --config cleanup.policy=delete \
    --config compression.type=gzip \
    --config min.insync.replicas=2

# ============================================================================
# TIERED STORAGE TOPICS (if enabled)
# ============================================================================
echo ""
echo "Creating tiered storage topics..."

create_topic "logs-archive" 3 3 \
    --config retention.ms=-1 \
    --config retention.bytes=-1 \
    --config cleanup.policy=delete \
    --config compression.type=gzip \
    --config min.insync.replicas=2 \
    --config remote.storage.enable=true 2>/dev/null || echo "  Note: Tiered storage not enabled, skipping remote.storage config"

# ============================================================================
# SUMMARY
# ============================================================================
echo ""
echo "============================================"
echo "Topic initialization complete!"
echo "============================================"
echo ""
echo "Topics created:"
kafka-topics --bootstrap-server kafka01:9092 --list | sort
echo ""
echo "============================================"
