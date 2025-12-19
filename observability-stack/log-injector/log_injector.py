#!/usr/bin/env python3
"""
Log Injector - Generate and inject realistic logs into Elasticsearch

This script generates realistic log data and injects it into an Elasticsearch
cluster for testing and demonstration purposes.

Features:
- Multi-host support with automatic failover
- Compatible with Elasticsearch 8.x and 9.x
- Configurable via environment variables or YAML config file
- Continuous injection with automatic reconnection
- Dynamic host/password configuration

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
from datetime import datetime, timezone
from typing import Generator, Dict, Any, List, Optional, Union
from pathlib import Path

try:
    import yaml
    YAML_AVAILABLE = True
except ImportError:
    YAML_AVAILABLE = False

from elasticsearch import Elasticsearch, helpers
from elasticsearch.exceptions import ConnectionError, TransportError, AuthenticationException

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

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
    'Database connection pool exhausted'
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
    'Configuration reloaded'
]

DEBUG_MESSAGES = [
    'Entering function processRequest',
    'Query executed: SELECT * FROM users WHERE id = ?',
    'Response serialization completed',
    'Validating request parameters',
    'Loading configuration from environment',
    'Establishing database connection',
    'Parsing JSON payload',
    'Computing recommendation scores'
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
    """Generate a random trace ID."""
    return hashlib.md5(str(random.random()).encode()).hexdigest()[:32]


def generate_span_id() -> str:
    """Generate a random span ID."""
    return hashlib.md5(str(random.random()).encode()).hexdigest()[:16]


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
                'AuthenticationError', 'PermissionError', 'DatabaseError'
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


def log_generator() -> Generator[Dict[str, Any], None, None]:
    """Generate a continuous stream of log entries."""
    generators = [
        (generate_application_log, 60),  # 60% application logs
        (generate_access_log, 30),       # 30% access logs
        (generate_metric_log, 10)        # 10% metric logs
    ]

    while not shutdown_requested:
        gen_func = weighted_choice({g[0]: g[1] for g in generators})
        yield gen_func()


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

def print_config_info(args):
    """Print current configuration info."""
    index_prefix = config.get('elasticsearch.index_prefix', 'logs', env_key='INDEX_PREFIX')
    hosts = config.get_list('elasticsearch.hosts', env_key='ES_HOSTS')
    if not hosts:
        hosts = [config.get('elasticsearch.host', 'https://es01:9200', env_key='ES_HOST')]

    logger.info("=" * 60)
    logger.info("Log Injector Starting")
    logger.info("=" * 60)
    logger.info(f"ES Hosts: {hosts}")
    logger.info(f"Injection Rate: {args.rate} logs/second")
    logger.info(f"Index Prefix: {index_prefix}")
    logger.info(f"Batch Size: {args.batch_size}")
    if args.duration:
        logger.info(f"Duration: {args.duration} seconds")
    else:
        logger.info("Duration: Infinite (Ctrl+C to stop)")
    logger.info("=" * 60)


def main():
    global config

    parser = argparse.ArgumentParser(description='Inject logs into Elasticsearch')
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
    args = parser.parse_args()

    # Reload config if config file specified
    if args.config:
        config = Config(args.config)

    print_config_info(args)

    # Create ES manager and connect
    es_manager = ElasticsearchManager()

    logger.info("Connecting to Elasticsearch...")
    if not es_manager.wait_for_ready():
        sys.exit(1)

    # Create index template
    ensure_index_template(es_manager)

    # Start injection
    logger.info("Starting log injection...")
    start_time = time.time()
    total_indexed = 0
    batch: List[Dict[str, Any]] = []
    last_status_time = start_time

    interval = 1.0 / args.rate if args.rate > 0 else 0.1
    gen = log_generator()

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
                indexed = bulk_index_logs(es_manager, batch)
                total_indexed += indexed

                # Log status periodically (every 10 seconds)
                current_time = time.time()
                if current_time - last_status_time >= 10:
                    elapsed = current_time - start_time
                    rate = total_indexed / elapsed if elapsed > 0 else 0
                    logger.info(f"Indexed {total_indexed} logs ({rate:.1f} logs/sec)")
                    last_status_time = current_time

                batch = []

            # Rate limiting
            time.sleep(interval)

    except Exception as e:
        logger.error(f"Error during injection: {e}")

    finally:
        # Index remaining logs
        if batch:
            indexed = bulk_index_logs(es_manager, batch)
            total_indexed += indexed

        elapsed = time.time() - start_time
        rate = total_indexed / elapsed if elapsed > 0 else 0

        logger.info("=" * 60)
        logger.info("Log Injection Complete")
        logger.info("=" * 60)
        logger.info(f"Total logs indexed: {total_indexed}")
        logger.info(f"Duration: {elapsed:.1f} seconds")
        logger.info(f"Average rate: {rate:.1f} logs/second")
        logger.info("=" * 60)


if __name__ == '__main__':
    main()
