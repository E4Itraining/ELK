#!/usr/bin/env python3
"""
Log Injector - Generate and inject realistic logs into Elasticsearch

This script generates realistic log data and injects it into an Elasticsearch
cluster for testing and demonstration purposes.

Usage:
    python log_injector.py [--rate LOGS_PER_SECOND] [--duration SECONDS]
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
from typing import Generator, Dict, Any, List
from elasticsearch import Elasticsearch, helpers
from elasticsearch.exceptions import ConnectionError, TransportError

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# ============================================================================
# CONFIGURATION
# ============================================================================

# Elasticsearch connection
ES_HOST = os.environ.get('ES_HOST', 'https://es01:9200')
ES_USER = os.environ.get('ES_USER', 'elastic')
ES_PASSWORD = os.environ.get('ES_PASSWORD', 'changeme')
ES_VERIFY_CERTS = os.environ.get('ES_VERIFY_CERTS', 'false').lower() == 'true'

# Injection settings
INJECTION_RATE = int(os.environ.get('INJECTION_RATE', '10'))
INDEX_PREFIX = os.environ.get('INDEX_PREFIX', 'logs')
BATCH_SIZE = 100

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

# Sample data for realistic log generation
SERVICES = [
    'api-gateway', 'auth-service', 'user-service', 'order-service',
    'payment-service', 'notification-service', 'inventory-service',
    'search-service', 'recommendation-engine', 'analytics-service'
]

ENVIRONMENTS = ['production', 'staging', 'development']
DATACENTERS = ['dc-us-east-1', 'dc-us-west-2', 'dc-eu-west-1', 'dc-ap-south-1']
HOSTS = [f'host-{i:03d}' for i in range(1, 21)]
VERSIONS = ['1.0.0', '1.1.0', '1.2.0', '2.0.0', '2.1.0']

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
    service = random.choice(SERVICES)

    log = {
        '@timestamp': datetime.now(timezone.utc).isoformat(),
        'level': level,
        'logger': f'{service}.{random.choice(["main", "handler", "service", "repository"])}',
        'message': generate_log_message(level),
        'service': {
            'name': service,
            'version': random.choice(VERSIONS),
            'environment': random.choice(ENVIRONMENTS)
        },
        'host': {
            'name': random.choice(HOSTS),
            'ip': generate_ip(),
            'datacenter': random.choice(DATACENTERS)
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
            'name': random.choice(SERVICES),
            'environment': random.choice(ENVIRONMENTS)
        },
        'host': {
            'name': random.choice(HOSTS)
        },
        'trace': {
            'id': generate_trace_id()
        }
    }


def generate_metric_log() -> Dict[str, Any]:
    """Generate a metric/system log entry."""
    service = random.choice(SERVICES)
    host = random.choice(HOSTS)

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
            'environment': random.choice(ENVIRONMENTS)
        },
        'host': {
            'name': host,
            'datacenter': random.choice(DATACENTERS)
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

def create_es_client() -> Elasticsearch:
    """Create and configure Elasticsearch client."""
    return Elasticsearch(
        [ES_HOST],
        basic_auth=(ES_USER, ES_PASSWORD),
        verify_certs=ES_VERIFY_CERTS,
        ssl_show_warn=False,
        request_timeout=30,
        max_retries=3,
        retry_on_timeout=True
    )


def ensure_index_template(es: Elasticsearch):
    """Create index template if it doesn't exist."""
    template_name = f'{INDEX_PREFIX}-template'

    template_body = {
        'index_patterns': [f'{INDEX_PREFIX}-*'],
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
        'priority': 100
    }

    try:
        es.indices.put_index_template(name=template_name, body=template_body)
        logger.info(f"Index template '{template_name}' created/updated")
    except Exception as e:
        logger.warning(f"Could not create index template: {e}")


def bulk_index_logs(es: Elasticsearch, logs: List[Dict[str, Any]]) -> int:
    """Bulk index logs into Elasticsearch."""
    today = datetime.now(timezone.utc).strftime('%Y.%m.%d')
    index_name = f'{INDEX_PREFIX}-{today}'

    actions = [
        {
            '_index': index_name,
            '_source': log
        }
        for log in logs
    ]

    try:
        success, failed = helpers.bulk(
            es,
            actions,
            raise_on_error=False,
            raise_on_exception=False
        )
        return success
    except Exception as e:
        logger.error(f"Bulk indexing error: {e}")
        return 0


# ============================================================================
# MAIN
# ============================================================================

def main():
    parser = argparse.ArgumentParser(description='Inject logs into Elasticsearch')
    parser.add_argument('--rate', type=int, default=INJECTION_RATE,
                       help=f'Logs per second (default: {INJECTION_RATE})')
    parser.add_argument('--duration', type=int, default=0,
                       help='Duration in seconds (0 = infinite)')
    parser.add_argument('--batch-size', type=int, default=BATCH_SIZE,
                       help=f'Batch size for bulk indexing (default: {BATCH_SIZE})')
    args = parser.parse_args()

    logger.info("=" * 60)
    logger.info("Log Injector Starting")
    logger.info("=" * 60)
    logger.info(f"ES Host: {ES_HOST}")
    logger.info(f"Injection Rate: {args.rate} logs/second")
    logger.info(f"Index Prefix: {INDEX_PREFIX}")
    logger.info(f"Batch Size: {args.batch_size}")
    if args.duration:
        logger.info(f"Duration: {args.duration} seconds")
    else:
        logger.info("Duration: Infinite (Ctrl+C to stop)")
    logger.info("=" * 60)

    # Connect to Elasticsearch
    logger.info("Connecting to Elasticsearch...")
    es = create_es_client()

    # Wait for ES to be ready
    max_retries = 30
    for i in range(max_retries):
        try:
            info = es.info()
            logger.info(f"Connected to Elasticsearch {info['version']['number']}")
            break
        except (ConnectionError, TransportError) as e:
            if i < max_retries - 1:
                logger.warning(f"Waiting for Elasticsearch... ({i+1}/{max_retries})")
                time.sleep(5)
            else:
                logger.error(f"Could not connect to Elasticsearch: {e}")
                sys.exit(1)

    # Create index template
    ensure_index_template(es)

    # Start injection
    logger.info("Starting log injection...")
    start_time = time.time()
    total_indexed = 0
    batch: List[Dict[str, Any]] = []

    interval = 1.0 / args.rate if args.rate > 0 else 0.1
    gen = log_generator()

    try:
        while not shutdown_requested:
            # Check duration limit
            if args.duration > 0 and (time.time() - start_time) >= args.duration:
                logger.info("Duration limit reached")
                break

            # Generate log
            log = next(gen)
            batch.append(log)

            # Index when batch is full
            if len(batch) >= args.batch_size:
                indexed = bulk_index_logs(es, batch)
                total_indexed += indexed

                elapsed = time.time() - start_time
                rate = total_indexed / elapsed if elapsed > 0 else 0
                logger.info(f"Indexed {total_indexed} logs ({rate:.1f} logs/sec)")

                batch = []

            # Rate limiting
            time.sleep(interval)

    except Exception as e:
        logger.error(f"Error during injection: {e}")

    finally:
        # Index remaining logs
        if batch:
            indexed = bulk_index_logs(es, batch)
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
