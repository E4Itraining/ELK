-- ============================================================================
-- KSQLDB INITIALIZATION QUERIES
-- ============================================================================
-- Stream processing for log analytics and real-time aggregations
-- ============================================================================

-- ============================================================================
-- SOURCE STREAMS
-- ============================================================================

-- Main logs stream
CREATE STREAM IF NOT EXISTS logs_stream (
    `@timestamp` VARCHAR,
    level VARCHAR,
    log_type VARCHAR,
    message VARCHAR,
    logger VARCHAR,
    service STRUCT<name VARCHAR, version VARCHAR, environment VARCHAR>,
    host STRUCT<name VARCHAR, ip VARCHAR, datacenter VARCHAR>,
    trace STRUCT<id VARCHAR, span_id VARCHAR>,
    http STRUCT<
        request STRUCT<method VARCHAR, path VARCHAR, user_agent VARCHAR>,
        response STRUCT<status_code INT, latency_ms INT>
    >,
    client STRUCT<ip VARCHAR>,
    error STRUCT<type VARCHAR, message VARCHAR>,
    business STRUCT<transaction_id VARCHAR, customer_segment VARCHAR, region VARCHAR>,
    sla STRUCT<tier VARCHAR, breach BOOLEAN>,
    sli STRUCT<latency_category VARCHAR, success BOOLEAN>
) WITH (
    KAFKA_TOPIC='logs',
    VALUE_FORMAT='JSON',
    TIMESTAMP='@timestamp',
    TIMESTAMP_FORMAT='yyyy-MM-dd''T''HH:mm:ss.SSSSSSXXX'
);

-- Error logs stream
CREATE STREAM IF NOT EXISTS error_logs_stream (
    `@timestamp` VARCHAR,
    level VARCHAR,
    message VARCHAR,
    service STRUCT<name VARCHAR, environment VARCHAR>,
    host STRUCT<name VARCHAR, datacenter VARCHAR>,
    error STRUCT<type VARCHAR, message VARCHAR, stack_trace VARCHAR>,
    trace STRUCT<id VARCHAR>
) WITH (
    KAFKA_TOPIC='logs-errors',
    VALUE_FORMAT='JSON'
);

-- ============================================================================
-- DERIVED STREAMS
-- ============================================================================

-- Filter only errors and warnings from main stream
CREATE STREAM IF NOT EXISTS logs_errors_warnings AS
SELECT
    `@timestamp`,
    level,
    message,
    service->name AS service_name,
    service->environment AS environment,
    host->datacenter AS datacenter,
    error->type AS error_type,
    trace->id AS trace_id
FROM logs_stream
WHERE level IN ('ERROR', 'FATAL', 'WARN')
EMIT CHANGES;

-- SLA breaches stream
CREATE STREAM IF NOT EXISTS sla_breaches_stream AS
SELECT
    `@timestamp`,
    service->name AS service_name,
    service->environment AS environment,
    sla->tier AS sla_tier,
    http->response->latency_ms AS latency_ms,
    sla->breach AS is_breach,
    trace->id AS trace_id,
    business->customer_segment AS customer_segment
FROM logs_stream
WHERE sla->breach = true
EMIT CHANGES;

-- High latency requests stream
CREATE STREAM IF NOT EXISTS high_latency_stream AS
SELECT
    `@timestamp`,
    service->name AS service_name,
    http->request->method AS http_method,
    http->request->path AS http_path,
    http->response->latency_ms AS latency_ms,
    http->response->status_code AS status_code,
    sli->latency_category AS latency_category
FROM logs_stream
WHERE http->response->latency_ms > 1000
EMIT CHANGES;

-- ============================================================================
-- AGGREGATION TABLES
-- ============================================================================

-- Error counts per service (tumbling window 1 minute)
CREATE TABLE IF NOT EXISTS error_counts_1m AS
SELECT
    service->name AS service_name,
    service->environment AS environment,
    COUNT(*) AS error_count,
    WINDOWSTART AS window_start,
    WINDOWEND AS window_end
FROM logs_stream
WINDOW TUMBLING (SIZE 1 MINUTE)
WHERE level IN ('ERROR', 'FATAL')
GROUP BY service->name, service->environment
EMIT CHANGES;

-- Error counts per service (tumbling window 5 minutes)
CREATE TABLE IF NOT EXISTS error_counts_5m AS
SELECT
    service->name AS service_name,
    service->environment AS environment,
    COUNT(*) AS error_count,
    WINDOWSTART AS window_start,
    WINDOWEND AS window_end
FROM logs_stream
WINDOW TUMBLING (SIZE 5 MINUTES)
WHERE level IN ('ERROR', 'FATAL')
GROUP BY service->name, service->environment
EMIT CHANGES;

-- Latency percentiles per service
CREATE TABLE IF NOT EXISTS latency_stats_1m AS
SELECT
    service->name AS service_name,
    COUNT(*) AS request_count,
    MIN(http->response->latency_ms) AS min_latency,
    MAX(http->response->latency_ms) AS max_latency,
    AVG(http->response->latency_ms) AS avg_latency,
    WINDOWSTART AS window_start,
    WINDOWEND AS window_end
FROM logs_stream
WINDOW TUMBLING (SIZE 1 MINUTE)
WHERE http IS NOT NULL AND http->response IS NOT NULL
GROUP BY service->name
EMIT CHANGES;

-- SLA breach counts
CREATE TABLE IF NOT EXISTS sla_breach_counts AS
SELECT
    service->name AS service_name,
    sla->tier AS sla_tier,
    COUNT(*) AS breach_count,
    WINDOWSTART AS window_start,
    WINDOWEND AS window_end
FROM logs_stream
WINDOW TUMBLING (SIZE 5 MINUTES)
WHERE sla->breach = true
GROUP BY service->name, sla->tier
EMIT CHANGES;

-- HTTP status code distribution
CREATE TABLE IF NOT EXISTS http_status_distribution AS
SELECT
    service->name AS service_name,
    http->response->status_code AS status_code,
    COUNT(*) AS request_count,
    WINDOWSTART AS window_start,
    WINDOWEND AS window_end
FROM logs_stream
WINDOW TUMBLING (SIZE 1 MINUTE)
WHERE http IS NOT NULL AND http->response IS NOT NULL
GROUP BY service->name, http->response->status_code
EMIT CHANGES;

-- Log level distribution per datacenter
CREATE TABLE IF NOT EXISTS log_level_by_datacenter AS
SELECT
    host->datacenter AS datacenter,
    level,
    COUNT(*) AS log_count,
    WINDOWSTART AS window_start,
    WINDOWEND AS window_end
FROM logs_stream
WINDOW TUMBLING (SIZE 5 MINUTES)
GROUP BY host->datacenter, level
EMIT CHANGES;

-- ============================================================================
-- ALERTING STREAMS
-- ============================================================================

-- Alert: High error rate (more than 100 errors per minute)
CREATE STREAM IF NOT EXISTS alerts_high_error_rate AS
SELECT
    service_name,
    environment,
    error_count,
    window_start,
    window_end,
    'HIGH_ERROR_RATE' AS alert_type,
    'critical' AS severity,
    CONCAT('High error rate detected: ', CAST(error_count AS VARCHAR), ' errors in 1 minute for ', service_name) AS alert_message
FROM error_counts_1m
WHERE error_count > 100
EMIT CHANGES;

-- Alert: Multiple SLA breaches
CREATE STREAM IF NOT EXISTS alerts_sla_breaches AS
SELECT
    service_name,
    sla_tier,
    breach_count,
    window_start,
    window_end,
    'SLA_BREACH' AS alert_type,
    CASE
        WHEN sla_tier = 'platinum' THEN 'critical'
        WHEN sla_tier = 'gold' THEN 'warning'
        ELSE 'info'
    END AS severity,
    CONCAT('SLA breaches detected: ', CAST(breach_count AS VARCHAR), ' breaches for ', sla_tier, ' tier in ', service_name) AS alert_message
FROM sla_breach_counts
WHERE breach_count > 10
EMIT CHANGES;

-- Unified alerts stream
CREATE STREAM IF NOT EXISTS alerts_unified WITH (
    KAFKA_TOPIC='alerts-stream',
    VALUE_FORMAT='JSON',
    PARTITIONS=3,
    REPLICAS=3
) AS
SELECT
    ROWTIME AS alert_time,
    alert_type,
    severity,
    alert_message,
    service_name,
    window_start,
    window_end
FROM alerts_high_error_rate
EMIT CHANGES;

-- ============================================================================
-- MATERIALIZED VIEWS FOR DASHBOARDS
-- ============================================================================

-- Service health summary (latest state)
CREATE TABLE IF NOT EXISTS service_health_summary AS
SELECT
    service->name AS service_name,
    service->environment AS environment,
    LATEST_BY_OFFSET(level) AS last_log_level,
    COUNT(*) AS total_logs,
    COUNT_DISTINCT(trace->id) AS unique_traces
FROM logs_stream
WINDOW TUMBLING (SIZE 5 MINUTES)
GROUP BY service->name, service->environment
EMIT CHANGES;

-- ============================================================================
-- OUTPUT STREAMS FOR DOWNSTREAM SYSTEMS
-- ============================================================================

-- Aggregated metrics stream (for Prometheus/Grafana)
CREATE STREAM IF NOT EXISTS metrics_aggregated WITH (
    KAFKA_TOPIC='logs-aggregated-1m',
    VALUE_FORMAT='JSON',
    PARTITIONS=3,
    REPLICAS=3
) AS
SELECT
    service_name,
    request_count,
    min_latency,
    max_latency,
    avg_latency,
    window_start,
    window_end
FROM latency_stats_1m
EMIT CHANGES;

-- ============================================================================
-- PRINT CONFIRMATION
-- ============================================================================
-- To verify streams/tables are created, run:
-- SHOW STREAMS;
-- SHOW TABLES;
-- DESCRIBE EXTENDED logs_stream;
