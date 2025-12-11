# ============================================================================
# KAFKA WITH JMX EXPORTER
# ============================================================================
# Image Confluent Kafka avec JMX Prometheus Exporter integre
# ============================================================================

ARG KAFKA_VERSION=7.5.0
FROM confluentinc/cp-kafka:${KAFKA_VERSION}

# Version du JMX Exporter
ARG JMX_EXPORTER_VERSION=0.20.0

# Installer wget si necessaire et telecharger JMX Exporter
USER root
RUN mkdir -p /usr/share/jmx_exporter && \
    curl -L -o /usr/share/jmx_exporter/jmx_prometheus_javaagent.jar \
    https://repo1.maven.org/maven2/io/prometheus/jmx/jmx_prometheus_javaagent/${JMX_EXPORTER_VERSION}/jmx_prometheus_javaagent-${JMX_EXPORTER_VERSION}.jar && \
    chmod 644 /usr/share/jmx_exporter/jmx_prometheus_javaagent.jar

# Copier la configuration JMX Exporter
COPY jmx-exporter-config.yml /usr/share/jmx_exporter/jmx-exporter-config.yml

USER appuser

# Les ports exposes
# 9092 - Kafka broker
# 9101 - JMX
# 7071 - JMX Exporter Prometheus metrics
EXPOSE 9092 9101 7071
