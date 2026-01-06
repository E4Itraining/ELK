#!/usr/bin/env python3
"""
Log Injector - Generate and inject realistic logs into Elasticsearch and/or Kafka

This script generates realistic log data and injects it into an Elasticsearch
cluster and/or Kafka topics for testing and demonstration purposes.

Features:
- Multi-host support with automatic failover for Elasticsearch
- Kafka producer with criteria-based topic routing
- Compatible with Elasticsearch 8.x and 9.x
- Configurable via environment variables or YAML config file
- Continuous injection with automatic reconnection
- Log enrichment with business context, SLA metadata, and correlation IDs
- Flexible routing rules based on log level, service, datacenter, etc.

Usage:
    python log_injector.py [--config CONFIG_FILE] [--rate LOGS_PER_SECOND] [--duration SECONDS]

Environment Variables:
    ES_HOSTS: Comma-separated list of ES hosts (e.g., "https://es01:9200,https://es02:9200")
    ES_HOST: Single ES host (fallback if ES_HOSTS not set)
    ES_USER: Elasticsearch username
    ES_PASSWORD: Elasticsearch password
    ES_API_KEY: API key for authentication (alternative to user/password)
    ES_VERIFY_CERTS: Verify SSL certificates (true/false)
    ES_CA_CERTS: Path to CA certificate file
    KAFKA_BOOTSTRAP_SERVERS: Comma-separated Kafka brokers
    KAFKA_ENABLED: Enable Kafka injection (true/false)
    INJECTION_TARGET: Target output (elasticsearch, kafka, both)
    INJECTION_RATE: Logs per second
    INDEX_PREFIX: Index name prefix
    CONFIG_FILE: Path to YAML configuration file
"""

import os
import sys
import time
import json
import random
import hashlib
import argparse
import signal
import logging
import uuid
from datetime import datetime, timezone, timedelta
from typing import Generator, Dict, Any, List, Optional, Callable, Tuple
from pathlib import Path
from dataclasses import dataclass, field
from enum import Enum

try:
    import yaml
    YAML_AVAILABLE = True
except ImportError:
    YAML_AVAILABLE = False

try:
    from kafka import KafkaProducer
    from kafka.errors import KafkaError, NoBrokersAvailable
    KAFKA_AVAILABLE = True
except ImportError:
    KAFKA_AVAILABLE = False
    KafkaProducer = None

from elasticsearch import Elasticsearch, helpers
from elasticsearch.exceptions import ConnectionError, TransportError, AuthenticationException

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


# ============================================================================
# ENUMS AND DATA CLASSES
# ============================================================================

class InjectionTarget(Enum):
    """Output target for log injection."""
    ELASTICSEARCH = "elasticsearch"
    KAFKA = "kafka"
    BOTH = "both"


class RoutingStrategy(Enum):
    """Strategy for routing logs to Kafka topics."""
    STATIC = "static"           # Single topic for all logs
    BY_LEVEL = "by_level"       # Route by log level (ERROR → logs-errors)
    BY_SERVICE = "by_service"   # Route by service name
    BY_DATACENTER = "by_datacenter"  # Route by datacenter
    BY_LOG_TYPE = "by_log_type"      # Route by log type (app, access, metric)
    BY_ENVIRONMENT = "by_environment"  # Route by environment
    CUSTOM = "custom"           # Custom routing rules


@dataclass
class RoutingRule:
    """Definition of a routing rule for Kafka topics."""
    name: str
    field: str                  # Field to match (e.g., "level", "service.name")
    values: Dict[str, str]      # Value to topic mapping
    default_topic: str          # Default if no match
    priority: int = 0           # Higher priority rules evaluated first


@dataclass
class EnrichmentConfig:
    """Configuration for log enrichment."""
    add_business_context: bool = True
    add_sla_metadata: bool = True
    add_correlation_chain: bool = True
    add_cost_attribution: bool = True
    add_security_context: bool = False
    custom_fields: Dict[str, Any] = field(default_factory=dict)


# ============================================================================
# CONFIGURATION
# ============================================================================

class Config:
    """Configuration manager supporting environment variables and YAML config."""

    def __init__(self, config_file: Optional[str] = None):
        self.config_file = config_file or os.environ.get('CONFIG_FILE')
        self._config: Dict[str, Any] = {}
        self._load_config()

    def _load_config(self):
        """Load configuration from file if available."""
        if self.config_file and Path(self.config_file).exists():
            if not YAML_AVAILABLE:
                logger.warning("PyYAML not installed, cannot load config file")
                return

            with open(self.config_file, 'r') as f:
                self._config = yaml.safe_load(f) or {}
            logger.info(f"Loaded configuration from {self.config_file}")

    def get(self, key: str, default: Any = None, env_key: Optional[str] = None) -> Any:
        """Get configuration value with priority: env var > config file > default."""
        env_key = env_key or key.upper().replace('.', '_')

        # Check environment variable first
        env_value = os.environ.get(env_key)
        if env_value is not None:
            return env_value

        # Check config file (supports nested keys with dot notation)
        value = self._config
        for part in key.split('.'):
            if isinstance(value, dict) and part in value:
                value = value[part]
            else:
                return default

        return value if value != self._config else default

    def get_bool(self, key: str, default: bool = False, env_key: Optional[str] = None) -> bool:
        """Get boolean configuration value."""
        value = self.get(key, default, env_key)
        if isinstance(value, bool):
            return value
        if isinstance(value, str):
            return value.lower() in ('true', '1', 'yes', 'on')
        return bool(value)

    def get_int(self, key: str, default: int = 0, env_key: Optional[str] = None) -> int:
        """Get integer configuration value."""
        value = self.get(key, default, env_key)
        try:
            return int(value)
        except (ValueError, TypeError):
            return default

    def get_float(self, key: str, default: float = 0.0, env_key: Optional[str] = None) -> float:
        """Get float configuration value."""
        value = self.get(key, default, env_key)
        try:
            return float(value)
        except (ValueError, TypeError):
            return default

    def get_list(self, key: str, default: Optional[List] = None, env_key: Optional[str] = None) -> List:
        """Get list configuration value (comma-separated in env vars)."""
        value = self.get(key, default, env_key)
        if value is None:
            return default or []
        if isinstance(value, list):
            return value
        if isinstance(value, str):
            return [v.strip() for v in value.split(',') if v.strip()]
        return default or []

    def get_dict(self, key: str, default: Optional[Dict] = None, env_key: Optional[str] = None) -> Dict:
        """Get dictionary configuration value."""
        value = self.get(key, default, env_key)
        if isinstance(value, dict):
            return value
        return default or {}

    def get_routing_rules(self) -> List[RoutingRule]:
        """Parse routing rules from configuration."""
        rules_config = self.get_dict('kafka.routing.rules', {})
        rules = []

        for name, rule_data in rules_config.items():
            if isinstance(rule_data, dict):
                rules.append(RoutingRule(
                    name=name,
                    field=rule_data.get('field', 'level'),
                    values=rule_data.get('values', {}),
                    default_topic=rule_data.get('default_topic', 'logs'),
                    priority=rule_data.get('priority', 0)
                ))

        # Sort by priority (highest first)
        rules.sort(key=lambda r: r.priority, reverse=True)
        return rules

    def get_enrichment_config(self) -> EnrichmentConfig:
        """Get enrichment configuration."""
        enrichment = self.get_dict('enrichment', {})
        return EnrichmentConfig(
            add_business_context=enrichment.get('business_context', True),
            add_sla_metadata=enrichment.get('sla_metadata', True),
            add_correlation_chain=enrichment.get('correlation_chain', True),
            add_cost_attribution=enrichment.get('cost_attribution', True),
            add_security_context=enrichment.get('security_context', False),
            custom_fields=enrichment.get('custom_fields', {})
        )


# Global configuration
config = Config()

# Graceful shutdown flag
shutdown_requested = False


def signal_handler(signum, frame):
    """Handle shutdown signals gracefully."""
    global shutdown_requested
    logger.info("Shutdown signal received. Finishing current batch...")
    shutdown_requested = True


signal.signal(signal.SIGINT, signal_handler)
signal.signal(signal.SIGTERM, signal_handler)


# ============================================================================
# LOG DATA GENERATORS
# ============================================================================

# Sample data for realistic log generation - can be overridden via config
def get_services() -> List[str]:
    """Get list of services from config or defaults."""
    return config.get_list('generators.services', [
        'api-gateway', 'auth-service', 'user-service', 'order-service',
        'payment-service', 'notification-service', 'inventory-service',
        'search-service', 'recommendation-engine', 'analytics-service'
    ])


def get_environments() -> List[str]:
    """Get list of environments from config or defaults."""
    return config.get_list('generators.environments', ['production', 'staging', 'development'])


def get_datacenters() -> List[str]:
    """Get list of datacenters from config or defaults."""
    return config.get_list('generators.datacenters',
                          ['dc-us-east-1', 'dc-us-west-2', 'dc-eu-west-1', 'dc-ap-south-1'])


def get_hosts() -> List[str]:
    """Get list of simulated hosts from config or generate defaults."""
    configured = config.get_list('generators.hosts')
    if configured:
        return configured

    # Generate host names based on configured count
    host_count = config.get_int('generators.host_count', 20)
    return [f'host-{i:03d}' for i in range(1, host_count + 1)]


# Business context data for enrichment
CUSTOMER_SEGMENTS = ['enterprise', 'business', 'premium', 'standard', 'trial']
COST_CENTERS = ['engineering', 'platform', 'infrastructure', 'product', 'analytics']
TEAMS = ['platform-team', 'api-team', 'payments-team', 'search-team', 'ml-team']
REGIONS = ['north-america', 'europe', 'asia-pacific', 'latin-america']

# SLA tiers with latency thresholds (ms)
SLA_TIERS = {
    'platinum': {'latency_p99': 100, 'availability': 99.99},
    'gold': {'latency_p99': 250, 'availability': 99.9},
    'silver': {'latency_p99': 500, 'availability': 99.5},
    'bronze': {'latency_p99': 1000, 'availability': 99.0}
}

VERSIONS = ['1.0.0', '1.1.0', '1.2.0', '2.0.0', '2.1.0', '3.0.0']

LOG_LEVELS = {
    'DEBUG': 5,
    'INFO': 70,
    'WARN': 15,
    'ERROR': 8,
    'FATAL': 2
}

HTTP_METHODS = ['GET', 'POST', 'PUT', 'DELETE', 'PATCH']
HTTP_STATUS_CODES = {
    200: 60, 201: 10, 204: 5,
    400: 8, 401: 5, 403: 3, 404: 5,
    500: 3, 502: 1, 503: 1
}

ENDPOINTS = [
    '/api/v1/users', '/api/v1/users/{id}',
    '/api/v1/orders', '/api/v1/orders/{id}',
    '/api/v1/products', '/api/v1/products/{id}',
    '/api/v1/auth/login', '/api/v1/auth/logout',
    '/api/v1/search', '/api/v1/recommendations',
    '/health', '/metrics', '/ready'
]

ERROR_MESSAGES = [
    'Connection timeout to database',
    'Failed to authenticate user',
    'Invalid request payload',
    'Rate limit exceeded',
    'Service unavailable',
    'Internal server error',
    'Resource not found',
    'Permission denied',
    'Token expired',
    'Database connection pool exhausted',
    'Circuit breaker open',
    'Upstream service timeout',
    'Message queue full',
    'Cache eviction failed'
]

INFO_MESSAGES = [
    'Request processed successfully',
    'User authenticated',
    'Order created',
    'Payment processed',
    'Notification sent',
    'Cache hit',
    'Cache miss - fetching from database',
    'Background job completed',
    'Health check passed',
    'Configuration reloaded',
    'Connection pool initialized',
    'Feature flag evaluated',
    'Audit log recorded'
]

DEBUG_MESSAGES = [
    'Entering function processRequest',
    'Query executed: SELECT * FROM users WHERE id = ?',
    'Response serialization completed',
    'Validating request parameters',
    'Loading configuration from environment',
    'Establishing database connection',
    'Parsing JSON payload',
    'Computing recommendation scores',
    'Cache key generated',
    'Transaction started'
]

USER_AGENTS = [
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36',
    'Mozilla/5.0 (iPhone; CPU iPhone OS 14_0 like Mac OS X)',
    'Mozilla/5.0 (Linux; Android 11; SM-G991B)',
    'curl/7.68.0',
    'python-requests/2.28.0',
    'PostmanRuntime/7.29.0',
    'Apache-HttpClient/4.5.13'
]


def weighted_choice(choices: Dict[Any, int]) -> Any:
    """Select a random item based on weights."""
    total = sum(choices.values())
    r = random.uniform(0, total)
    cumulative = 0
    for item, weight in choices.items():
        cumulative += weight
        if r <= cumulative:
            return item
    return list(choices.keys())[-1]


def generate_trace_id() -> str:
    """Generate a random trace ID (W3C format)."""
    return uuid.uuid4().hex


def generate_span_id() -> str:
    """Generate a random span ID."""
    return uuid.uuid4().hex[:16]


def generate_correlation_id() -> str:
    """Generate a correlation ID for request chains."""
    return f"corr-{uuid.uuid4().hex[:12]}"


def generate_transaction_id() -> str:
    """Generate a business transaction ID."""
    return f"txn-{uuid.uuid4().hex[:8].upper()}"


def generate_ip() -> str:
    """Generate a random IP address."""
    return f"{random.randint(1, 255)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"


def generate_log_message(level: str) -> str:
    """Generate a log message based on level."""
    if level in ['ERROR', 'FATAL']:
        return random.choice(ERROR_MESSAGES)
    elif level == 'DEBUG':
        return random.choice(DEBUG_MESSAGES)
    else:
        return random.choice(INFO_MESSAGES)


# ============================================================================
# LOG ENRICHMENT
# ============================================================================

class LogEnricher:
    """Enriches log entries with additional context and metadata."""

    def __init__(self, config: EnrichmentConfig):
        self.config = config
        self._correlation_chains: Dict[str, List[str]] = {}  # trace_id -> span_ids

    def enrich(self, log: Dict[str, Any]) -> Dict[str, Any]:
        """Apply all configured enrichments to a log entry."""
        enriched = log.copy()

        if self.config.add_business_context:
            enriched = self._add_business_context(enriched)

        if self.config.add_sla_metadata:
            enriched = self._add_sla_metadata(enriched)

        if self.config.add_correlation_chain:
            enriched = self._add_correlation_chain(enriched)

        if self.config.add_cost_attribution:
            enriched = self._add_cost_attribution(enriched)

        if self.config.add_security_context:
            enriched = self._add_security_context(enriched)

        # Add custom fields
        if self.config.custom_fields:
            enriched['custom'] = self.config.custom_fields.copy()

        # Add enrichment metadata
        enriched['_enrichment'] = {
            'version': '1.0',
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'enricher': 'log-injector'
        }

        return enriched

    def _add_business_context(self, log: Dict[str, Any]) -> Dict[str, Any]:
        """Add business context to the log."""
        log['business'] = {
            'transaction_id': generate_transaction_id(),
            'customer_segment': random.choice(CUSTOMER_SEGMENTS),
            'region': random.choice(REGIONS),
            'channel': random.choice(['web', 'mobile', 'api', 'partner']),
            'feature_flags': {
                'new_checkout': random.choice([True, False]),
                'ab_test_variant': random.choice(['control', 'variant_a', 'variant_b'])
            }
        }

        # Add order value for order-related services
        service_name = log.get('service', {}).get('name', '')
        if 'order' in service_name or 'payment' in service_name:
            log['business']['order_value'] = round(random.uniform(10, 1000), 2)
            log['business']['currency'] = random.choice(['USD', 'EUR', 'GBP'])

        return log

    def _add_sla_metadata(self, log: Dict[str, Any]) -> Dict[str, Any]:
        """Add SLA/SLO metadata to the log."""
        sla_tier = random.choice(list(SLA_TIERS.keys()))
        sla_config = SLA_TIERS[sla_tier]

        # Check if latency exceeds SLA
        latency = log.get('http', {}).get('response', {}).get('latency_ms', 0)
        sla_breach = latency > sla_config['latency_p99'] if latency else False

        log['sla'] = {
            'tier': sla_tier,
            'latency_budget_ms': sla_config['latency_p99'],
            'availability_target': sla_config['availability'],
            'breach': sla_breach,
            'remaining_budget_ms': max(0, sla_config['latency_p99'] - latency) if latency else None
        }

        # Add SLI indicators
        log['sli'] = {
            'latency_category': self._categorize_latency(latency),
            'success': log.get('http', {}).get('response', {}).get('status_code', 200) < 500,
            'error_budget_impact': 1 if sla_breach else 0
        }

        return log

    def _categorize_latency(self, latency_ms: int) -> str:
        """Categorize latency into buckets."""
        if not latency_ms:
            return 'unknown'
        if latency_ms < 50:
            return 'fast'
        elif latency_ms < 200:
            return 'normal'
        elif latency_ms < 500:
            return 'slow'
        elif latency_ms < 2000:
            return 'very_slow'
        else:
            return 'critical'

    def _add_correlation_chain(self, log: Dict[str, Any]) -> Dict[str, Any]:
        """Add correlation chain for distributed tracing."""
        trace_id = log.get('trace', {}).get('id')
        if not trace_id:
            return log

        # Simulate request chain (parent/child relationships)
        if trace_id not in self._correlation_chains:
            self._correlation_chains[trace_id] = []

        chain = self._correlation_chains[trace_id]
        current_span = log.get('trace', {}).get('span_id')

        log['correlation'] = {
            'id': generate_correlation_id(),
            'chain_depth': len(chain),
            'parent_span_id': chain[-1] if chain else None,
            'root_span_id': chain[0] if chain else current_span,
            'is_root': len(chain) == 0
        }

        # Add current span to chain (limit chain length)
        if len(chain) < 10 and current_span:
            chain.append(current_span)

        # Clean up old chains periodically
        if len(self._correlation_chains) > 1000:
            # Keep only recent chains
            keys_to_remove = list(self._correlation_chains.keys())[:-500]
            for key in keys_to_remove:
                del self._correlation_chains[key]

        return log

    def _add_cost_attribution(self, log: Dict[str, Any]) -> Dict[str, Any]:
        """Add cost attribution metadata."""
        service_name = log.get('service', {}).get('name', 'unknown')

        # Map services to cost centers
        service_to_cost_center = {
            'api-gateway': 'platform',
            'auth-service': 'platform',
            'user-service': 'product',
            'order-service': 'product',
            'payment-service': 'product',
            'notification-service': 'platform',
            'inventory-service': 'product',
            'search-service': 'analytics',
            'recommendation-engine': 'analytics',
            'analytics-service': 'analytics'
        }

        log['cost'] = {
            'center': service_to_cost_center.get(service_name, 'engineering'),
            'team': random.choice(TEAMS),
            'project': f"proj-{random.randint(100, 999)}",
            'estimated_compute_cost': round(random.uniform(0.0001, 0.01), 6),
            'resource_tier': random.choice(['standard', 'compute-optimized', 'memory-optimized'])
        }

        return log

    def _add_security_context(self, log: Dict[str, Any]) -> Dict[str, Any]:
        """Add security context to the log."""
        log['security'] = {
            'authenticated': random.choice([True, True, True, False]),  # 75% authenticated
            'auth_method': random.choice(['jwt', 'oauth2', 'api_key', 'session']),
            'user_role': random.choice(['admin', 'user', 'service', 'anonymous']),
            'ip_reputation': random.choice(['trusted', 'unknown', 'suspicious']),
            'geo_risk': random.choice(['low', 'medium', 'high']),
            'session_age_minutes': random.randint(0, 480)
        }

        return log


# ============================================================================
# LOG GENERATORS
# ============================================================================

def generate_application_log() -> Dict[str, Any]:
    """Generate a realistic application log entry."""
    level = weighted_choice(LOG_LEVELS)
    service = random.choice(get_services())
    environments = get_environments()
    datacenters = get_datacenters()
    hosts = get_hosts()

    log = {
        '@timestamp': datetime.now(timezone.utc).isoformat(),
        'level': level,
        'log_type': 'application',
        'logger': f'{service}.{random.choice(["main", "handler", "service", "repository"])}',
        'message': generate_log_message(level),
        'service': {
            'name': service,
            'version': random.choice(VERSIONS),
            'environment': random.choice(environments)
        },
        'host': {
            'name': random.choice(hosts),
            'ip': generate_ip(),
            'datacenter': random.choice(datacenters)
        },
        'trace': {
            'id': generate_trace_id(),
            'span_id': generate_span_id()
        },
        'process': {
            'pid': random.randint(1000, 65000),
            'thread': {
                'id': random.randint(1, 100),
                'name': f'worker-{random.randint(1, 16)}'
            }
        }
    }

    # Add HTTP context for some logs
    if random.random() > 0.3:
        status_code = weighted_choice(HTTP_STATUS_CODES)
        log['http'] = {
            'request': {
                'method': random.choice(HTTP_METHODS),
                'path': random.choice(ENDPOINTS).replace('{id}', str(random.randint(1, 10000))),
                'user_agent': random.choice(USER_AGENTS)
            },
            'response': {
                'status_code': status_code,
                'latency_ms': random.randint(1, 2000) if status_code < 500 else random.randint(5000, 30000)
            }
        }
        log['client'] = {
            'ip': generate_ip()
        }

    # Add error details for error logs
    if level in ['ERROR', 'FATAL']:
        log['error'] = {
            'type': random.choice([
                'ConnectionError', 'TimeoutError', 'ValidationError',
                'AuthenticationError', 'PermissionError', 'DatabaseError',
                'CircuitBreakerOpen', 'RateLimitExceeded', 'ServiceUnavailable'
            ]),
            'message': log['message'],
            'stack_trace': f"at {service}.Handler.process(Handler.java:{random.randint(50, 500)})\n" +
                          f"at {service}.Service.execute(Service.java:{random.randint(50, 500)})"
        }

    # Add metrics context occasionally
    if random.random() > 0.7:
        log['metrics'] = {
            'memory_usage_mb': random.randint(100, 2000),
            'cpu_percent': random.uniform(0.1, 100),
            'active_connections': random.randint(1, 500),
            'queue_size': random.randint(0, 1000)
        }

    return log


def generate_access_log() -> Dict[str, Any]:
    """Generate a realistic access/HTTP log entry."""
    status_code = weighted_choice(HTTP_STATUS_CODES)
    method = random.choice(HTTP_METHODS)
    path = random.choice(ENDPOINTS).replace('{id}', str(random.randint(1, 10000)))
    environments = get_environments()
    hosts = get_hosts()

    # Latency based on status code
    if status_code >= 500:
        latency = random.randint(5000, 30000)
    elif status_code >= 400:
        latency = random.randint(10, 500)
    else:
        latency = random.randint(1, 500)

    response_size = random.randint(100, 50000) if method == 'GET' else random.randint(0, 1000)

    return {
        '@timestamp': datetime.now(timezone.utc).isoformat(),
        'level': 'INFO' if status_code < 400 else ('WARN' if status_code < 500 else 'ERROR'),
        'log_type': 'access',
        'message': f'{method} {path} {status_code} {latency}ms',
        'http': {
            'request': {
                'method': method,
                'path': path,
                'query_string': f'page={random.randint(1,100)}&limit={random.choice([10,20,50,100])}' if random.random() > 0.5 else '',
                'body_bytes': random.randint(0, 10000) if method in ['POST', 'PUT', 'PATCH'] else 0,
                'user_agent': random.choice(USER_AGENTS),
                'referrer': f'https://example.com/{random.choice(["home", "products", "orders", "search"])}'
            },
            'response': {
                'status_code': status_code,
                'body_bytes': response_size,
                'latency_ms': latency
            }
        },
        'client': {
            'ip': generate_ip(),
            'geo': {
                'country': random.choice(['US', 'UK', 'DE', 'FR', 'JP', 'AU', 'BR', 'IN']),
                'city': random.choice(['New York', 'London', 'Berlin', 'Paris', 'Tokyo', 'Sydney'])
            }
        },
        'service': {
            'name': random.choice(get_services()),
            'environment': random.choice(environments)
        },
        'host': {
            'name': random.choice(hosts)
        },
        'trace': {
            'id': generate_trace_id()
        }
    }


def generate_metric_log() -> Dict[str, Any]:
    """Generate a metric/system log entry."""
    service = random.choice(get_services())
    hosts = get_hosts()
    host = random.choice(hosts)
    datacenters = get_datacenters()
    environments = get_environments()

    cpu_usage = random.uniform(0, 100)
    memory_usage = random.uniform(30, 95)

    # Determine level based on resource usage
    if cpu_usage > 90 or memory_usage > 90:
        level = 'ERROR'
        message = 'Resource usage critical'
    elif cpu_usage > 75 or memory_usage > 80:
        level = 'WARN'
        message = 'Resource usage high'
    else:
        level = 'INFO'
        message = 'System metrics collected'

    return {
        '@timestamp': datetime.now(timezone.utc).isoformat(),
        'level': level,
        'log_type': 'metric',
        'message': message,
        'service': {
            'name': service,
            'environment': random.choice(environments)
        },
        'host': {
            'name': host,
            'datacenter': random.choice(datacenters)
        },
        'system': {
            'cpu': {
                'usage_percent': round(cpu_usage, 2),
                'load_1m': round(random.uniform(0, 4), 2),
                'load_5m': round(random.uniform(0, 4), 2),
                'load_15m': round(random.uniform(0, 4), 2)
            },
            'memory': {
                'usage_percent': round(memory_usage, 2),
                'used_bytes': random.randint(1000000000, 8000000000),
                'total_bytes': 8000000000
            },
            'disk': {
                'usage_percent': round(random.uniform(20, 85), 2),
                'read_bytes': random.randint(0, 100000000),
                'write_bytes': random.randint(0, 100000000)
            },
            'network': {
                'in_bytes': random.randint(0, 1000000000),
                'out_bytes': random.randint(0, 1000000000),
                'connections': random.randint(10, 1000)
            }
        },
        'jvm': {
            'heap': {
                'used_bytes': random.randint(100000000, 1000000000),
                'max_bytes': 1000000000,
                'usage_percent': round(random.uniform(30, 95), 2)
            },
            'gc': {
                'young_count': random.randint(0, 100),
                'old_count': random.randint(0, 10),
                'total_time_ms': random.randint(0, 5000)
            },
            'threads': {
                'count': random.randint(50, 500),
                'peak': random.randint(100, 600)
            }
        }
    }


def log_generator(enricher: Optional[LogEnricher] = None) -> Generator[Dict[str, Any], None, None]:
    """Generate a continuous stream of log entries."""
    generators = [
        (generate_application_log, 60),  # 60% application logs
        (generate_access_log, 30),       # 30% access logs
        (generate_metric_log, 10)        # 10% metric logs
    ]

    while not shutdown_requested:
        gen_func = weighted_choice({g[0]: g[1] for g in generators})
        log = gen_func()

        if enricher:
            log = enricher.enrich(log)

        yield log


# ============================================================================
# KAFKA MANAGER
# ============================================================================

class KafkaManager:
    """Manages Kafka producer with topic routing based on criteria and metrics."""

    def __init__(self):
        self.producer: Optional[KafkaProducer] = None
        self.routing_rules: List[RoutingRule] = []
        self.default_topic: str = 'logs'
        self.routing_strategy: RoutingStrategy = RoutingStrategy.STATIC
        self._topic_stats: Dict[str, int] = {}
        # Producer metrics
        self._metrics: Dict[str, Any] = {
            'messages_sent': 0,
            'messages_failed': 0,
            'bytes_sent': 0,
            'send_latency_sum_ms': 0,
            'send_latency_count': 0,
            'batch_count': 0,
            'last_error': None,
            'last_error_time': None,
            'start_time': None,
        }
        # Header routing configuration
        self._header_routing_enabled: bool = False
        self._header_routing_rules: Dict[str, Dict[str, str]] = {}

    def _get_bootstrap_servers(self) -> List[str]:
        """Get Kafka bootstrap servers from configuration."""
        servers = config.get_list('kafka.bootstrap_servers',
                                  env_key='KAFKA_BOOTSTRAP_SERVERS')
        if servers:
            return servers
        return ['kafka01:9092', 'kafka02:9092', 'kafka03:9092']

    def connect(self) -> bool:
        """Establish connection to Kafka cluster."""
        if not KAFKA_AVAILABLE:
            logger.error("kafka-python not installed. Install with: pip install kafka-python")
            return False

        bootstrap_servers = self._get_bootstrap_servers()
        logger.info(f"Connecting to Kafka brokers: {bootstrap_servers}")

        try:
            # Configure producer
            producer_config = {
                'bootstrap_servers': bootstrap_servers,
                'value_serializer': lambda v: json.dumps(v).encode('utf-8'),
                'key_serializer': lambda k: k.encode('utf-8') if k else None,
                'acks': config.get('kafka.acks', 'all'),
                'retries': config.get_int('kafka.retries', 3),
                'batch_size': config.get_int('kafka.batch_size', 16384),
                'linger_ms': config.get_int('kafka.linger_ms', 10),
                'compression_type': config.get('kafka.compression', 'gzip'),
                'max_request_size': config.get_int('kafka.max_request_size', 1048576),
            }

            # Add security config if present
            security_protocol = config.get('kafka.security_protocol')
            if security_protocol:
                producer_config['security_protocol'] = security_protocol

            sasl_mechanism = config.get('kafka.sasl_mechanism')
            if sasl_mechanism:
                producer_config['sasl_mechanism'] = sasl_mechanism
                producer_config['sasl_plain_username'] = config.get('kafka.sasl_username')
                producer_config['sasl_plain_password'] = config.get('kafka.sasl_password')

            self.producer = KafkaProducer(**producer_config)

            # Load routing configuration
            self._load_routing_config()

            # Load header routing configuration
            self._load_header_routing_config()

            # Initialize metrics start time
            self._metrics['start_time'] = time.time()

            logger.info("Connected to Kafka cluster successfully")
            return True

        except NoBrokersAvailable as e:
            logger.error(f"No Kafka brokers available: {e}")
            return False
        except KafkaError as e:
            logger.error(f"Kafka connection error: {e}")
            return False
        except Exception as e:
            logger.error(f"Unexpected error connecting to Kafka: {e}")
            return False

    def _load_routing_config(self):
        """Load routing rules from configuration."""
        strategy = config.get('kafka.routing.strategy', 'static')
        self.routing_strategy = RoutingStrategy(strategy.lower())
        self.default_topic = config.get('kafka.routing.default_topic', 'logs')

        # Load custom rules
        self.routing_rules = config.get_routing_rules()

        # Add built-in routing rules based on strategy
        if self.routing_strategy == RoutingStrategy.BY_LEVEL:
            self.routing_rules.append(RoutingRule(
                name='level_routing',
                field='level',
                values={
                    'ERROR': 'logs-errors',
                    'FATAL': 'logs-errors',
                    'WARN': 'logs-warnings',
                    'INFO': 'logs-info',
                    'DEBUG': 'logs-debug'
                },
                default_topic=self.default_topic,
                priority=100
            ))
        elif self.routing_strategy == RoutingStrategy.BY_SERVICE:
            # Dynamic routing by service name
            pass  # Handled in route_to_topic
        elif self.routing_strategy == RoutingStrategy.BY_DATACENTER:
            pass  # Handled in route_to_topic
        elif self.routing_strategy == RoutingStrategy.BY_LOG_TYPE:
            self.routing_rules.append(RoutingRule(
                name='log_type_routing',
                field='log_type',
                values={
                    'application': 'logs-application',
                    'access': 'logs-access',
                    'metric': 'logs-metrics'
                },
                default_topic=self.default_topic,
                priority=100
            ))
        elif self.routing_strategy == RoutingStrategy.BY_ENVIRONMENT:
            self.routing_rules.append(RoutingRule(
                name='environment_routing',
                field='service.environment',
                values={
                    'production': 'logs-prod',
                    'staging': 'logs-staging',
                    'development': 'logs-dev'
                },
                default_topic=self.default_topic,
                priority=100
            ))

        logger.info(f"Routing strategy: {self.routing_strategy.value}, "
                   f"default topic: {self.default_topic}, "
                   f"{len(self.routing_rules)} custom rules")

    def _load_header_routing_config(self):
        """Load header-based routing configuration."""
        self._header_routing_enabled = config.get_bool('kafka.header_routing.enabled', False)
        if not self._header_routing_enabled:
            return

        # Load header routing rules
        # Format: { "header_name": { "header_value": "target_topic" } }
        self._header_routing_rules = config.get_dict('kafka.header_routing.rules', {
            'X-Priority': {
                'critical': 'logs-critical',
                'high': 'logs-errors',
                'normal': 'logs',
                'low': 'logs-debug'
            },
            'X-Environment': {
                'production': 'logs-prod',
                'staging': 'logs-staging',
                'development': 'logs-dev'
            },
            'X-Log-Type': {
                'audit': 'logs-audit',
                'security': 'logs-security',
                'performance': 'logs-performance'
            }
        })

        logger.info(f"Header routing enabled with {len(self._header_routing_rules)} header rules")

    def generate_headers(self, log: Dict[str, Any]) -> List[Tuple[str, bytes]]:
        """Generate Kafka headers from log entry for downstream routing."""
        headers = []

        # Add standard headers
        headers.append(('X-Log-Level', log.get('level', 'INFO').encode('utf-8')))
        headers.append(('X-Log-Type', log.get('log_type', 'application').encode('utf-8')))

        # Add service info
        service_name = self._get_nested_value(log, 'service.name')
        if service_name:
            headers.append(('X-Service-Name', service_name.encode('utf-8')))

        service_env = self._get_nested_value(log, 'service.environment')
        if service_env:
            headers.append(('X-Environment', service_env.encode('utf-8')))

        # Add datacenter
        datacenter = self._get_nested_value(log, 'host.datacenter')
        if datacenter:
            headers.append(('X-Datacenter', datacenter.encode('utf-8')))

        # Add trace ID for correlation
        trace_id = self._get_nested_value(log, 'trace.id')
        if trace_id:
            headers.append(('X-Trace-ID', trace_id.encode('utf-8')))

        # Add priority based on log level and SLA breach
        priority = 'normal'
        level = log.get('level', 'INFO')
        if level in ['ERROR', 'FATAL']:
            priority = 'high'
        elif level == 'DEBUG':
            priority = 'low'

        sla_breach = self._get_nested_value(log, 'sla.breach')
        if sla_breach:
            priority = 'critical'

        headers.append(('X-Priority', priority.encode('utf-8')))

        # Add timestamp
        headers.append(('X-Timestamp', log.get('@timestamp', '').encode('utf-8')))

        # Add producer metadata
        headers.append(('X-Producer', 'log-injector'.encode('utf-8')))
        headers.append(('X-Producer-Version', '2.0'.encode('utf-8')))

        return headers

    def route_by_headers(self, headers: List[Tuple[str, bytes]]) -> Optional[str]:
        """Route to topic based on headers."""
        if not self._header_routing_enabled:
            return None

        headers_dict = {h[0]: h[1].decode('utf-8') for h in headers}

        for header_name, routing_map in self._header_routing_rules.items():
            header_value = headers_dict.get(header_name)
            if header_value and header_value in routing_map:
                return routing_map[header_value]

        return None

    def _get_nested_value(self, data: Dict[str, Any], field: str) -> Any:
        """Get a value from nested dictionary using dot notation."""
        value = data
        for part in field.split('.'):
            if isinstance(value, dict) and part in value:
                value = value[part]
            else:
                return None
        return value

    def route_to_topic(self, log: Dict[str, Any]) -> str:
        """Determine the target topic for a log entry based on routing rules."""
        # Check static strategy first
        if self.routing_strategy == RoutingStrategy.STATIC:
            return self.default_topic

        # Dynamic routing strategies
        if self.routing_strategy == RoutingStrategy.BY_SERVICE:
            service_name = self._get_nested_value(log, 'service.name')
            if service_name:
                return f"logs-{service_name}"
            return self.default_topic

        if self.routing_strategy == RoutingStrategy.BY_DATACENTER:
            datacenter = self._get_nested_value(log, 'host.datacenter')
            if datacenter:
                # Convert dc-us-east-1 to logs-us-east-1
                dc_name = datacenter.replace('dc-', '')
                return f"logs-{dc_name}"
            return self.default_topic

        # Apply custom routing rules
        for rule in self.routing_rules:
            field_value = self._get_nested_value(log, rule.field)
            if field_value and str(field_value) in rule.values:
                return rule.values[str(field_value)]

        return self.default_topic

    def get_partition_key(self, log: Dict[str, Any]) -> Optional[str]:
        """Generate a partition key for consistent routing."""
        key_field = config.get('kafka.partition_key_field', 'service.name')
        key_value = self._get_nested_value(log, key_field)
        return str(key_value) if key_value else None

    def send(self, log: Dict[str, Any]) -> bool:
        """Send a log entry to the appropriate Kafka topic with headers."""
        if not self.producer:
            return False

        start_time = time.time()

        # Generate headers
        headers = self.generate_headers(log)

        # Determine topic - header routing takes precedence if enabled
        topic = self.route_by_headers(headers)
        if not topic:
            topic = self.route_to_topic(log)

        key = self.get_partition_key(log)

        try:
            # Serialize log to calculate size
            log_bytes = json.dumps(log).encode('utf-8')
            message_size = len(log_bytes)

            future = self.producer.send(topic, value=log, key=key, headers=headers)
            # Don't wait for result (async), but track it
            future.add_callback(lambda metadata: self._on_send_success(topic, metadata, message_size, start_time))
            future.add_errback(lambda e: self._on_send_error(topic, e))

            # Track topic stats
            self._topic_stats[topic] = self._topic_stats.get(topic, 0) + 1
            return True

        except KafkaError as e:
            self._metrics['messages_failed'] += 1
            self._metrics['last_error'] = str(e)
            self._metrics['last_error_time'] = datetime.now(timezone.utc).isoformat()
            logger.error(f"Failed to send to Kafka topic {topic}: {e}")
            return False

    def _on_send_success(self, topic: str, metadata, message_size: int, start_time: float):
        """Callback for successful send with metrics tracking."""
        latency_ms = (time.time() - start_time) * 1000
        self._metrics['messages_sent'] += 1
        self._metrics['bytes_sent'] += message_size
        self._metrics['send_latency_sum_ms'] += latency_ms
        self._metrics['send_latency_count'] += 1

    def _on_send_error(self, topic: str, error):
        """Callback for failed send with metrics tracking."""
        self._metrics['messages_failed'] += 1
        self._metrics['last_error'] = str(error)
        self._metrics['last_error_time'] = datetime.now(timezone.utc).isoformat()
        logger.warning(f"Kafka send to {topic} failed: {error}")

    def send_batch(self, logs: List[Dict[str, Any]]) -> int:
        """Send a batch of logs to Kafka."""
        if not self.producer:
            return 0

        success_count = 0
        for log in logs:
            if self.send(log):
                success_count += 1

        # Flush to ensure all messages are sent
        self.producer.flush()
        return success_count

    def get_topic_stats(self) -> Dict[str, int]:
        """Get statistics about messages sent to each topic."""
        return self._topic_stats.copy()

    def get_metrics(self) -> Dict[str, Any]:
        """Get comprehensive producer metrics."""
        metrics = self._metrics.copy()

        # Calculate derived metrics
        if metrics['send_latency_count'] > 0:
            metrics['avg_send_latency_ms'] = metrics['send_latency_sum_ms'] / metrics['send_latency_count']
        else:
            metrics['avg_send_latency_ms'] = 0

        if metrics['start_time']:
            uptime_seconds = time.time() - metrics['start_time']
            metrics['uptime_seconds'] = uptime_seconds
            if uptime_seconds > 0:
                metrics['messages_per_second'] = metrics['messages_sent'] / uptime_seconds
                metrics['bytes_per_second'] = metrics['bytes_sent'] / uptime_seconds
            else:
                metrics['messages_per_second'] = 0
                metrics['bytes_per_second'] = 0

        metrics['success_rate'] = (
            metrics['messages_sent'] / (metrics['messages_sent'] + metrics['messages_failed'])
            if (metrics['messages_sent'] + metrics['messages_failed']) > 0
            else 1.0
        )

        metrics['topic_distribution'] = self._topic_stats.copy()
        metrics['header_routing_enabled'] = self._header_routing_enabled

        return metrics

    def print_metrics(self):
        """Print formatted metrics to logger."""
        metrics = self.get_metrics()
        logger.info("=" * 60)
        logger.info("KAFKA PRODUCER METRICS")
        logger.info("=" * 60)
        logger.info(f"Messages sent:     {metrics['messages_sent']:,}")
        logger.info(f"Messages failed:   {metrics['messages_failed']:,}")
        logger.info(f"Success rate:      {metrics['success_rate']:.2%}")
        logger.info(f"Bytes sent:        {metrics['bytes_sent']:,}")
        logger.info(f"Avg latency:       {metrics['avg_send_latency_ms']:.2f} ms")
        logger.info(f"Messages/sec:      {metrics.get('messages_per_second', 0):.2f}")
        logger.info(f"Bytes/sec:         {metrics.get('bytes_per_second', 0):.2f}")
        logger.info(f"Header routing:    {'enabled' if metrics['header_routing_enabled'] else 'disabled'}")
        logger.info("-" * 60)
        logger.info("Topic distribution:")
        for topic, count in sorted(metrics['topic_distribution'].items(), key=lambda x: -x[1]):
            logger.info(f"  {topic}: {count:,}")
        logger.info("=" * 60)

    def close(self):
        """Close the Kafka producer."""
        if self.producer:
            self.producer.flush()
            self.producer.close()
            logger.info("Kafka producer closed")


# ============================================================================
# ELASTICSEARCH CLIENT
# ============================================================================

class ElasticsearchManager:
    """Manages Elasticsearch connections with multi-host support and auto-reconnect."""

    def __init__(self):
        self.client: Optional[Elasticsearch] = None
        self.es_version: Optional[str] = None
        self.es_major_version: int = 0
        self._last_connect_attempt: float = 0
        self._reconnect_delay: float = 5.0

    def _get_hosts(self) -> List[str]:
        """Get list of Elasticsearch hosts from configuration."""
        # Try ES_HOSTS first (comma-separated list)
        hosts = config.get_list('elasticsearch.hosts', env_key='ES_HOSTS')
        if hosts:
            return hosts

        # Fall back to single ES_HOST
        single_host = config.get('elasticsearch.host', 'https://es01:9200', env_key='ES_HOST')
        return [single_host]

    def _get_auth(self) -> Dict[str, Any]:
        """Get authentication configuration."""
        auth_config = {}

        # Check for API key first (preferred for ES 8+)
        api_key = config.get('elasticsearch.api_key', env_key='ES_API_KEY')
        if api_key:
            auth_config['api_key'] = api_key
            return auth_config

        # Fall back to basic auth
        user = config.get('elasticsearch.user', 'elastic', env_key='ES_USER')
        password = config.get('elasticsearch.password', 'changeme', env_key='ES_PASSWORD')
        auth_config['basic_auth'] = (user, password)

        return auth_config

    def _get_ssl_config(self) -> Dict[str, Any]:
        """Get SSL/TLS configuration."""
        ssl_config = {}

        verify_certs = config.get_bool('elasticsearch.verify_certs', False, env_key='ES_VERIFY_CERTS')
        ssl_config['verify_certs'] = verify_certs
        ssl_config['ssl_show_warn'] = False

        ca_certs = config.get('elasticsearch.ca_certs', env_key='ES_CA_CERTS')
        if ca_certs:
            ssl_config['ca_certs'] = ca_certs

        return ssl_config

    def connect(self) -> bool:
        """Establish connection to Elasticsearch cluster."""
        hosts = self._get_hosts()
        auth_config = self._get_auth()
        ssl_config = self._get_ssl_config()

        logger.info(f"Connecting to Elasticsearch hosts: {hosts}")

        try:
            self.client = Elasticsearch(
                hosts,
                **auth_config,
                **ssl_config,
                request_timeout=120,
                max_retries=3,
                retry_on_timeout=True,
                sniff_on_start=False,  # Disable sniffing for container environments
                sniff_on_node_failure=False
            )

            # Verify connection and get version
            info = self.client.info()
            self.es_version = info['version']['number']
            self.es_major_version = int(self.es_version.split('.')[0])

            logger.info(f"Connected to Elasticsearch {self.es_version}")

            # Log compatibility info
            if self.es_major_version >= 9:
                logger.info("Running in Elasticsearch 9.x compatibility mode")
            elif self.es_major_version >= 8:
                logger.info("Running in Elasticsearch 8.x compatibility mode")

            return True

        except AuthenticationException as e:
            logger.error(f"Authentication failed: {e}")
            return False
        except (ConnectionError, TransportError) as e:
            logger.error(f"Connection failed: {e}")
            return False
        except Exception as e:
            logger.error(f"Unexpected error during connection: {e}")
            return False

    def ensure_connected(self) -> bool:
        """Ensure client is connected, reconnect if necessary."""
        if self.client is None:
            return self.connect()

        try:
            self.client.ping()
            return True
        except Exception:
            logger.warning("Lost connection to Elasticsearch, reconnecting...")
            return self.connect()

    def wait_for_ready(self, max_retries: int = 30, retry_delay: float = 5.0) -> bool:
        """Wait for Elasticsearch to be ready."""
        for i in range(max_retries):
            if shutdown_requested:
                return False

            if self.connect():
                return True

            if i < max_retries - 1:
                logger.warning(f"Waiting for Elasticsearch... ({i+1}/{max_retries})")
                time.sleep(retry_delay)

        logger.error("Could not connect to Elasticsearch after all retries")
        return False

    def get_client(self) -> Optional[Elasticsearch]:
        """Get the Elasticsearch client, ensuring connection."""
        if self.ensure_connected():
            return self.client
        return None


def ensure_index_template(es_manager: ElasticsearchManager):
    """Create index template if it doesn't exist."""
    es = es_manager.get_client()
    if not es:
        return

    index_prefix = config.get('elasticsearch.index_prefix', 'logs', env_key='INDEX_PREFIX')
    template_name = f'{index_prefix}-template'

    # Template body - compatible with ES 8.x and 9.x
    template_body = {
        'index_patterns': [f'{index_prefix}-*'],
        'template': {
            'settings': {
                'number_of_shards': 1,
                'number_of_replicas': 1,
                'refresh_interval': '5s'
            },
            'mappings': {
                'properties': {
                    '@timestamp': {'type': 'date'},
                    'level': {'type': 'keyword'},
                    'log_type': {'type': 'keyword'},
                    'message': {'type': 'text'},
                    'logger': {'type': 'keyword'},
                    'service': {
                        'properties': {
                            'name': {'type': 'keyword'},
                            'version': {'type': 'keyword'},
                            'environment': {'type': 'keyword'}
                        }
                    },
                    'host': {
                        'properties': {
                            'name': {'type': 'keyword'},
                            'ip': {'type': 'ip'},
                            'datacenter': {'type': 'keyword'}
                        }
                    },
                    'trace': {
                        'properties': {
                            'id': {'type': 'keyword'},
                            'span_id': {'type': 'keyword'}
                        }
                    },
                    'correlation': {
                        'properties': {
                            'id': {'type': 'keyword'},
                            'chain_depth': {'type': 'integer'},
                            'parent_span_id': {'type': 'keyword'},
                            'root_span_id': {'type': 'keyword'},
                            'is_root': {'type': 'boolean'}
                        }
                    },
                    'http': {
                        'properties': {
                            'request': {
                                'properties': {
                                    'method': {'type': 'keyword'},
                                    'path': {'type': 'keyword'},
                                    'user_agent': {'type': 'text'}
                                }
                            },
                            'response': {
                                'properties': {
                                    'status_code': {'type': 'integer'},
                                    'latency_ms': {'type': 'integer'},
                                    'body_bytes': {'type': 'long'}
                                }
                            }
                        }
                    },
                    'client': {
                        'properties': {
                            'ip': {'type': 'ip'},
                            'geo': {
                                'properties': {
                                    'country': {'type': 'keyword'},
                                    'city': {'type': 'keyword'}
                                }
                            }
                        }
                    },
                    'error': {
                        'properties': {
                            'type': {'type': 'keyword'},
                            'message': {'type': 'text'},
                            'stack_trace': {'type': 'text'}
                        }
                    },
                    'business': {
                        'properties': {
                            'transaction_id': {'type': 'keyword'},
                            'customer_segment': {'type': 'keyword'},
                            'region': {'type': 'keyword'},
                            'channel': {'type': 'keyword'},
                            'order_value': {'type': 'float'},
                            'currency': {'type': 'keyword'}
                        }
                    },
                    'sla': {
                        'properties': {
                            'tier': {'type': 'keyword'},
                            'latency_budget_ms': {'type': 'integer'},
                            'availability_target': {'type': 'float'},
                            'breach': {'type': 'boolean'},
                            'remaining_budget_ms': {'type': 'integer'}
                        }
                    },
                    'sli': {
                        'properties': {
                            'latency_category': {'type': 'keyword'},
                            'success': {'type': 'boolean'},
                            'error_budget_impact': {'type': 'integer'}
                        }
                    },
                    'cost': {
                        'properties': {
                            'center': {'type': 'keyword'},
                            'team': {'type': 'keyword'},
                            'project': {'type': 'keyword'},
                            'estimated_compute_cost': {'type': 'float'},
                            'resource_tier': {'type': 'keyword'}
                        }
                    },
                    'security': {
                        'properties': {
                            'authenticated': {'type': 'boolean'},
                            'auth_method': {'type': 'keyword'},
                            'user_role': {'type': 'keyword'},
                            'ip_reputation': {'type': 'keyword'},
                            'geo_risk': {'type': 'keyword'},
                            'session_age_minutes': {'type': 'integer'}
                        }
                    },
                    'system': {
                        'properties': {
                            'cpu': {'properties': {'usage_percent': {'type': 'float'}}},
                            'memory': {'properties': {'usage_percent': {'type': 'float'}}}
                        }
                    }
                }
            }
        },
        'priority': 200
    }

    try:
        es.indices.put_index_template(name=template_name, **template_body)
        logger.info(f"Index template '{template_name}' created/updated")
    except Exception as e:
        logger.warning(f"Could not create index template: {e}")


def bulk_index_logs(es_manager: ElasticsearchManager, logs: List[Dict[str, Any]]) -> int:
    """Bulk index logs into Elasticsearch with retry logic."""
    es = es_manager.get_client()
    if not es:
        logger.error("No Elasticsearch connection available")
        return 0

    index_prefix = config.get('elasticsearch.index_prefix', 'logs', env_key='INDEX_PREFIX')
    today = datetime.now(timezone.utc).strftime('%Y.%m.%d')
    index_name = f'{index_prefix}-{today}'

    actions = [
        {
            '_index': index_name,
            '_source': log
        }
        for log in logs
    ]

    max_retries = 3
    for attempt in range(max_retries):
        try:
            # Use es.options() for ES 8+ compatible request options
            es_with_timeout = es.options(request_timeout=120)
            success, failed = helpers.bulk(
                es_with_timeout,
                actions,
                chunk_size=500,
                raise_on_error=False,
                raise_on_exception=False
            )

            if failed:
                logger.warning(f"Some documents failed to index: {len(failed)} failures")

            return success

        except (ConnectionError, TransportError) as e:
            if attempt < max_retries - 1:
                logger.warning(f"Bulk indexing failed, retrying ({attempt + 1}/{max_retries}): {e}")
                time.sleep(2 ** attempt)  # Exponential backoff
                es_manager.ensure_connected()
            else:
                logger.error(f"Bulk indexing error after {max_retries} attempts: {e}")
                return 0
        except Exception as e:
            logger.error(f"Unexpected bulk indexing error: {e}")
            return 0

    return 0


# ============================================================================
# MAIN
# ============================================================================

def print_config_info(args, injection_target: InjectionTarget, kafka_enabled: bool):
    """Print current configuration info."""
    index_prefix = config.get('elasticsearch.index_prefix', 'logs', env_key='INDEX_PREFIX')
    es_hosts = config.get_list('elasticsearch.hosts', env_key='ES_HOSTS')
    if not es_hosts:
        es_hosts = [config.get('elasticsearch.host', 'https://es01:9200', env_key='ES_HOST')]

    kafka_servers = config.get_list('kafka.bootstrap_servers', env_key='KAFKA_BOOTSTRAP_SERVERS')
    routing_strategy = config.get('kafka.routing.strategy', 'static')

    logger.info("=" * 70)
    logger.info("Log Injector Starting")
    logger.info("=" * 70)
    logger.info(f"Injection Target: {injection_target.value}")
    logger.info(f"Injection Rate: {args.rate} logs/second")
    logger.info(f"Batch Size: {args.batch_size}")

    if injection_target in [InjectionTarget.ELASTICSEARCH, InjectionTarget.BOTH]:
        logger.info(f"ES Hosts: {es_hosts}")
        logger.info(f"Index Prefix: {index_prefix}")

    if injection_target in [InjectionTarget.KAFKA, InjectionTarget.BOTH]:
        logger.info(f"Kafka Servers: {kafka_servers}")
        logger.info(f"Routing Strategy: {routing_strategy}")

    enrichment_config = config.get_enrichment_config()
    logger.info(f"Enrichment: business={enrichment_config.add_business_context}, "
               f"sla={enrichment_config.add_sla_metadata}, "
               f"correlation={enrichment_config.add_correlation_chain}")

    if args.duration:
        logger.info(f"Duration: {args.duration} seconds")
    else:
        logger.info("Duration: Infinite (Ctrl+C to stop)")
    logger.info("=" * 70)


def main():
    global config

    parser = argparse.ArgumentParser(description='Inject logs into Elasticsearch and/or Kafka')
    parser.add_argument('--config', '-c', type=str,
                       help='Path to YAML configuration file')
    parser.add_argument('--rate', type=int,
                       default=config.get_int('injection.rate', 10, env_key='INJECTION_RATE'),
                       help='Logs per second (default: 10)')
    parser.add_argument('--duration', type=int, default=0,
                       help='Duration in seconds (0 = infinite)')
    parser.add_argument('--batch-size', type=int,
                       default=config.get_int('injection.batch_size', 100, env_key='BATCH_SIZE'),
                       help='Batch size for bulk indexing (default: 100)')
    parser.add_argument('--target', type=str,
                       default=config.get('injection.target', 'elasticsearch', env_key='INJECTION_TARGET'),
                       choices=['elasticsearch', 'kafka', 'both'],
                       help='Injection target (default: elasticsearch)')
    parser.add_argument('--no-enrichment', action='store_true',
                       help='Disable log enrichment')
    args = parser.parse_args()

    # Reload config if config file specified
    if args.config:
        config = Config(args.config)

    # Determine injection target
    injection_target = InjectionTarget(args.target.lower())
    kafka_enabled = injection_target in [InjectionTarget.KAFKA, InjectionTarget.BOTH]
    es_enabled = injection_target in [InjectionTarget.ELASTICSEARCH, InjectionTarget.BOTH]

    print_config_info(args, injection_target, kafka_enabled)

    # Initialize enricher
    enricher = None
    if not args.no_enrichment:
        enrichment_config = config.get_enrichment_config()
        enricher = LogEnricher(enrichment_config)
        logger.info("Log enrichment enabled")

    # Create managers and connect
    es_manager = None
    kafka_manager = None

    if es_enabled:
        es_manager = ElasticsearchManager()
        logger.info("Connecting to Elasticsearch...")
        if not es_manager.wait_for_ready():
            if injection_target == InjectionTarget.ELASTICSEARCH:
                sys.exit(1)
            else:
                logger.warning("Elasticsearch not available, continuing with Kafka only")
                es_manager = None
        else:
            # Create index template
            ensure_index_template(es_manager)

    if kafka_enabled:
        if not KAFKA_AVAILABLE:
            logger.error("kafka-python not installed. Install with: pip install kafka-python")
            if injection_target == InjectionTarget.KAFKA:
                sys.exit(1)
        else:
            kafka_manager = KafkaManager()
            logger.info("Connecting to Kafka...")
            if not kafka_manager.connect():
                if injection_target == InjectionTarget.KAFKA:
                    sys.exit(1)
                else:
                    logger.warning("Kafka not available, continuing with Elasticsearch only")
                    kafka_manager = None

    # Verify at least one output is available
    if not es_manager and not kafka_manager:
        logger.error("No output targets available. Exiting.")
        sys.exit(1)

    # Start injection
    logger.info("Starting log injection...")
    start_time = time.time()
    total_indexed_es = 0
    total_indexed_kafka = 0
    batch: List[Dict[str, Any]] = []
    last_status_time = start_time

    interval = 1.0 / args.rate if args.rate > 0 else 0.1
    gen = log_generator(enricher)

    try:
        while not shutdown_requested:
            # Check duration limit
            if args.duration > 0 and (time.time() - start_time) >= args.duration:
                logger.info("Duration limit reached")
                break

            # Generate log
            try:
                log = next(gen)
            except StopIteration:
                break

            batch.append(log)

            # Index when batch is full
            if len(batch) >= args.batch_size:
                if es_manager:
                    indexed = bulk_index_logs(es_manager, batch)
                    total_indexed_es += indexed

                if kafka_manager:
                    indexed = kafka_manager.send_batch(batch)
                    total_indexed_kafka += indexed

                # Log status periodically (every 10 seconds)
                current_time = time.time()
                if current_time - last_status_time >= 10:
                    elapsed = current_time - start_time
                    if es_manager:
                        rate_es = total_indexed_es / elapsed if elapsed > 0 else 0
                        logger.info(f"ES: {total_indexed_es} logs ({rate_es:.1f}/sec)")
                    if kafka_manager:
                        rate_kafka = total_indexed_kafka / elapsed if elapsed > 0 else 0
                        topic_stats = kafka_manager.get_topic_stats()
                        logger.info(f"Kafka: {total_indexed_kafka} logs ({rate_kafka:.1f}/sec), "
                                   f"topics: {topic_stats}")
                    last_status_time = current_time

                batch = []

            # Rate limiting
            time.sleep(interval)

    except Exception as e:
        logger.error(f"Error during injection: {e}")

    finally:
        # Index remaining logs
        if batch:
            if es_manager:
                indexed = bulk_index_logs(es_manager, batch)
                total_indexed_es += indexed
            if kafka_manager:
                indexed = kafka_manager.send_batch(batch)
                total_indexed_kafka += indexed

        # Close Kafka producer
        if kafka_manager:
            kafka_manager.close()

        elapsed = time.time() - start_time

        logger.info("=" * 70)
        logger.info("Log Injection Complete")
        logger.info("=" * 70)
        if es_manager:
            rate_es = total_indexed_es / elapsed if elapsed > 0 else 0
            logger.info(f"Elasticsearch: {total_indexed_es} logs ({rate_es:.1f}/sec)")
        if kafka_manager:
            rate_kafka = total_indexed_kafka / elapsed if elapsed > 0 else 0
            logger.info(f"Kafka: {total_indexed_kafka} logs ({rate_kafka:.1f}/sec)")
            logger.info(f"Topic distribution: {kafka_manager.get_topic_stats()}")
        logger.info(f"Duration: {elapsed:.1f} seconds")
        logger.info("=" * 70)


if __name__ == '__main__':
    main()
