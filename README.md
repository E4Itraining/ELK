# Log Injector for Elasticsearch

A lightweight Python tool that generates realistic log data and injects it into Elasticsearch clusters. Designed for testing, demonstrations, and observability platform validation.

## Overview

Log Injector simulates a microservices environment by generating three types of realistic log entries:

- **Application Logs** (60%) — Service-level logs with trace context, error details, and performance metrics
- **Access Logs** (30%) — HTTP request/response logs with latency, status codes, and geo-location data
- **System Metrics** (10%) — Infrastructure metrics including CPU, memory, disk, network, and JVM statistics

The tool supports configurable injection rates, graceful shutdown, automatic index template creation, and bulk indexing for optimal performance.

## Features

- Realistic log generation with weighted distributions for log levels and HTTP status codes
- Distributed tracing support (trace IDs and span IDs)
- Multi-service simulation (10 microservices across 4 datacenters)
- Configurable injection rate and duration
- Automatic Elasticsearch index template management
- Bulk indexing with retry logic
- Graceful shutdown handling (SIGINT/SIGTERM)
- Non-root container execution for security
- Environment-based configuration

## Quick Start

### Using Docker Compose

Add the log injector to your existing Elasticsearch stack:

```yaml
services:
  log-injector:
    build: .
    environment:
      ES_HOST: https://es01:9200
      ES_USER: elastic
      ES_PASSWORD: ${ELASTIC_PASSWORD}
      ES_VERIFY_CERTS: "false"
      INJECTION_RATE: "50"
      INDEX_PREFIX: logs
    depends_on:
      - es01
    restart: unless-stopped
```

### Using Docker

Build and run the container:

```bash
# Build the image
docker build -t log-injector .

# Run with environment variables
docker run -d \
  -e ES_HOST=https://elasticsearch:9200 \
  -e ES_USER=elastic \
  -e ES_PASSWORD=your_password \
  -e INJECTION_RATE=100 \
  --network your_network \
  log-injector
```

### Running Locally

```bash
# Install dependencies
pip install -r requirements.txt

# Run the injector
python log_injector.py --rate 50 --duration 300
```

## Configuration

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `ES_HOST` | `https://es01:9200` | Elasticsearch endpoint URL |
| `ES_USER` | `elastic` | Elasticsearch username |
| `ES_PASSWORD` | `changeme` | Elasticsearch password |
| `ES_VERIFY_CERTS` | `false` | Enable/disable TLS certificate verification |
| `INJECTION_RATE` | `10` | Target logs per second |
| `INDEX_PREFIX` | `logs` | Index name prefix (creates `{prefix}-YYYY.MM.DD`) |

### Command Line Arguments

```bash
python log_injector.py [OPTIONS]

Options:
  --rate INTEGER       Logs per second (default: 10, overrides INJECTION_RATE)
  --duration INTEGER   Duration in seconds (0 = infinite, default: 0)
  --batch-size INTEGER Batch size for bulk indexing (default: 100)
```

## Generated Log Structure

### Application Log Example

```json
{
  "@timestamp": "2024-01-15T10:30:45.123Z",
  "level": "ERROR",
  "logger": "order-service.handler",
  "message": "Connection timeout to database",
  "service": {
    "name": "order-service",
    "version": "2.1.0",
    "environment": "production"
  },
  "host": {
    "name": "host-007",
    "ip": "10.0.1.45",
    "datacenter": "dc-eu-west-1"
  },
  "trace": {
    "id": "a1b2c3d4e5f6789012345678",
    "span_id": "abcd1234efgh5678"
  },
  "http": {
    "request": {
      "method": "POST",
      "path": "/api/v1/orders",
      "user_agent": "Mozilla/5.0..."
    },
    "response": {
      "status_code": 500,
      "latency_ms": 15234
    }
  },
  "error": {
    "type": "ConnectionError",
    "message": "Connection timeout to database",
    "stack_trace": "at order-service.Handler.process..."
  }
}
```

### Access Log Example

```json
{
  "@timestamp": "2024-01-15T10:30:46.456Z",
  "level": "INFO",
  "log_type": "access",
  "message": "GET /api/v1/products/1234 200 45ms",
  "http": {
    "request": {
      "method": "GET",
      "path": "/api/v1/products/1234",
      "query_string": "page=1&limit=20",
      "user_agent": "curl/7.68.0"
    },
    "response": {
      "status_code": 200,
      "body_bytes": 4523,
      "latency_ms": 45
    }
  },
  "client": {
    "ip": "203.0.113.42",
    "geo": {
      "country": "FR",
      "city": "Paris"
    }
  },
  "trace": {
    "id": "b2c3d4e5f6a78901234567890"
  }
}
```

### System Metrics Example

```json
{
  "@timestamp": "2024-01-15T10:30:47.789Z",
  "level": "WARN",
  "log_type": "metric",
  "message": "Resource usage high",
  "service": {
    "name": "api-gateway",
    "environment": "production"
  },
  "host": {
    "name": "host-003",
    "datacenter": "dc-us-east-1"
  },
  "system": {
    "cpu": {
      "usage_percent": 78.5,
      "load_1m": 2.34,
      "load_5m": 1.89,
      "load_15m": 1.56
    },
    "memory": {
      "usage_percent": 82.3,
      "used_bytes": 6584000000,
      "total_bytes": 8000000000
    },
    "disk": {
      "usage_percent": 65.2,
      "read_bytes": 45000000,
      "write_bytes": 23000000
    },
    "network": {
      "in_bytes": 890000000,
      "out_bytes": 450000000,
      "connections": 234
    }
  },
  "jvm": {
    "heap": {
      "used_bytes": 650000000,
      "max_bytes": 1000000000,
      "usage_percent": 65.0
    },
    "gc": {
      "young_count": 45,
      "old_count": 3,
      "total_time_ms": 1234
    },
    "threads": {
      "count": 156,
      "peak": 189
    }
  }
}
```

## Simulated Environment

The injector simulates a distributed microservices architecture:

### Services

| Service | Description |
|---------|-------------|
| `api-gateway` | Main entry point |
| `auth-service` | Authentication & authorization |
| `user-service` | User management |
| `order-service` | Order processing |
| `payment-service` | Payment handling |
| `notification-service` | Notifications & alerts |
| `inventory-service` | Inventory management |
| `search-service` | Search functionality |
| `recommendation-engine` | ML-based recommendations |
| `analytics-service` | Analytics processing |

### Infrastructure

- **20 hosts** (`host-001` to `host-020`)
- **4 datacenters** (US East, US West, EU West, AP South)
- **3 environments** (production, staging, development)
- **5 service versions** (1.0.0 to 2.1.0)

### Log Level Distribution

| Level | Probability |
|-------|-------------|
| DEBUG | 5% |
| INFO | 70% |
| WARN | 15% |
| ERROR | 8% |
| FATAL | 2% |

### HTTP Status Code Distribution

| Status | Probability |
|--------|-------------|
| 200 OK | 60% |
| 201 Created | 10% |
| 204 No Content | 5% |
| 400 Bad Request | 8% |
| 401 Unauthorized | 5% |
| 403 Forbidden | 3% |
| 404 Not Found | 5% |
| 500 Internal Error | 3% |
| 502 Bad Gateway | 1% |
| 503 Unavailable | 1% |

## Index Template

The injector automatically creates an index template (`{prefix}-template`) with optimized mappings for all fields including:

- Proper date parsing for `@timestamp`
- IP field types for addresses
- Keyword types for searchable fields
- Text types for full-text search on messages

## Performance Tuning

### High-Volume Injection

For high-volume scenarios (1000+ logs/sec):

```bash
# Increase batch size for better throughput
python log_injector.py --rate 1000 --batch-size 500
```

### Resource Considerations

- **Memory**: ~50-100MB depending on batch size
- **CPU**: Minimal, scales with injection rate
- **Network**: Proportional to log volume (~1KB per log average)

## Monitoring the Injector

The injector logs its progress to stdout:

```
2024-01-15 10:30:00 - INFO - Log Injector Starting
2024-01-15 10:30:00 - INFO - ES Host: https://es01:9200
2024-01-15 10:30:00 - INFO - Injection Rate: 50 logs/second
2024-01-15 10:30:05 - INFO - Connected to Elasticsearch 8.11.0
2024-01-15 10:30:05 - INFO - Index template 'logs-template' created/updated
2024-01-15 10:30:10 - INFO - Indexed 500 logs (49.8 logs/sec)
```

## Graceful Shutdown

The injector handles SIGINT (Ctrl+C) and SIGTERM signals gracefully:

1. Completes the current batch
2. Indexes any remaining logs
3. Reports final statistics
4. Exits cleanly

## Use Cases

- **Observability Platform Testing** — Validate dashboards, alerts, and queries with realistic data
- **Performance Benchmarking** — Test Elasticsearch cluster performance under load
- **Demo Environments** — Populate demo systems with realistic log patterns
- **Training & Workshops** — Provide hands-on data for observability training
- **CI/CD Integration Testing** — Validate log pipelines in automated tests

## Requirements

- Python 3.11+
- Elasticsearch 8.x
- Network access to Elasticsearch cluster

## License

MIT License

## Contributing

Contributions are welcome! Please feel free to submit issues or pull requests.
