"""
Technical Monitoring Module
===========================

Monitors technical aspects of AI systems including:
- Latency (total, TTFT, inference, network)
- Throughput (tokens/sec, requests/min)
- Error rates and types
- Rate limiting
- Cache performance
- Streaming metrics
"""

import time
import logging
import hashlib
import statistics
from datetime import datetime, timezone
from typing import Dict, List, Optional, Any, Callable
from dataclasses import dataclass, field
from enum import Enum
from collections import defaultdict
from threading import Lock

from .config import Config, TechnicalConfig

logger = logging.getLogger(__name__)


class RequestStatus(Enum):
    """Request status enumeration."""
    SUCCESS = "success"
    ERROR = "error"
    TIMEOUT = "timeout"
    RATE_LIMITED = "rate_limited"
    CANCELLED = "cancelled"


class ErrorType(Enum):
    """Error type classification."""
    NETWORK = "network"
    TIMEOUT = "timeout"
    RATE_LIMIT = "rate_limit"
    AUTHENTICATION = "authentication"
    INVALID_REQUEST = "invalid_request"
    MODEL_ERROR = "model_error"
    CONTENT_FILTER = "content_filter"
    SERVER_ERROR = "server_error"
    UNKNOWN = "unknown"


@dataclass
class LatencyMetrics:
    """Latency measurements for a request."""
    total_ms: float = 0.0
    time_to_first_token_ms: Optional[float] = None
    inference_ms: Optional[float] = None
    network_ms: Optional[float] = None
    queue_ms: Optional[float] = None
    preprocessing_ms: Optional[float] = None
    postprocessing_ms: Optional[float] = None


@dataclass
class ThroughputMetrics:
    """Throughput measurements."""
    tokens_per_second: float = 0.0
    requests_per_minute: float = 0.0
    concurrent_requests: int = 0


@dataclass
class TokenMetrics:
    """Token usage metrics."""
    input: int = 0
    output: int = 0
    total: int = 0
    cached: int = 0


@dataclass
class ErrorMetrics:
    """Error information."""
    type: ErrorType = ErrorType.UNKNOWN
    code: Optional[str] = None
    message: Optional[str] = None
    retryable: bool = False
    retry_count: int = 0


@dataclass
class RateLimitMetrics:
    """Rate limit information."""
    limited: bool = False
    remaining_requests: Optional[int] = None
    remaining_tokens: Optional[int] = None
    reset_at: Optional[datetime] = None


@dataclass
class CacheMetrics:
    """Cache performance metrics."""
    hit: bool = False
    key: Optional[str] = None
    ttl_seconds: Optional[int] = None


@dataclass
class StreamingMetrics:
    """Streaming response metrics."""
    enabled: bool = False
    chunks_count: int = 0
    first_chunk_ms: Optional[float] = None
    last_chunk_ms: Optional[float] = None


@dataclass
class TechnicalMetric:
    """Complete technical metric for a single request."""
    request_id: str
    trace_id: Optional[str] = None
    span_id: Optional[str] = None
    provider: str = ""
    model: str = ""
    model_version: Optional[str] = None
    endpoint: Optional[str] = None
    operation: str = "completion"
    environment: str = "production"
    region: Optional[str] = None
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    status: RequestStatus = RequestStatus.SUCCESS
    status_code: Optional[int] = None
    latency: LatencyMetrics = field(default_factory=LatencyMetrics)
    throughput: ThroughputMetrics = field(default_factory=ThroughputMetrics)
    tokens: TokenMetrics = field(default_factory=TokenMetrics)
    error: Optional[ErrorMetrics] = None
    rate_limit: RateLimitMetrics = field(default_factory=RateLimitMetrics)
    cache: CacheMetrics = field(default_factory=CacheMetrics)
    streaming: StreamingMetrics = field(default_factory=StreamingMetrics)
    context: Dict[str, str] = field(default_factory=dict)
    infrastructure: Dict[str, str] = field(default_factory=dict)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for Elasticsearch indexing."""
        doc = {
            "@timestamp": self.timestamp.isoformat(),
            "request_id": self.request_id,
            "provider": self.provider,
            "model": self.model,
            "operation": self.operation,
            "environment": self.environment,
            "status": self.status.value,
            "latency": {
                "total_ms": self.latency.total_ms,
            },
            "throughput": {
                "tokens_per_second": self.throughput.tokens_per_second,
                "requests_per_minute": self.throughput.requests_per_minute,
                "concurrent_requests": self.throughput.concurrent_requests,
            },
            "tokens": {
                "input": self.tokens.input,
                "output": self.tokens.output,
                "total": self.tokens.total,
                "cached": self.tokens.cached,
            },
            "rate_limit": {
                "limited": self.rate_limit.limited,
            },
            "cache": {
                "hit": self.cache.hit,
            },
            "streaming": {
                "enabled": self.streaming.enabled,
                "chunks_count": self.streaming.chunks_count,
            },
        }

        # Add optional fields
        if self.trace_id:
            doc["trace_id"] = self.trace_id
        if self.span_id:
            doc["span_id"] = self.span_id
        if self.model_version:
            doc["model_version"] = self.model_version
        if self.endpoint:
            doc["endpoint"] = self.endpoint
        if self.region:
            doc["region"] = self.region
        if self.status_code:
            doc["status_code"] = self.status_code

        # Add latency details
        if self.latency.time_to_first_token_ms is not None:
            doc["latency"]["time_to_first_token_ms"] = self.latency.time_to_first_token_ms
        if self.latency.inference_ms is not None:
            doc["latency"]["inference_ms"] = self.latency.inference_ms
        if self.latency.network_ms is not None:
            doc["latency"]["network_ms"] = self.latency.network_ms
        if self.latency.queue_ms is not None:
            doc["latency"]["queue_ms"] = self.latency.queue_ms
        if self.latency.preprocessing_ms is not None:
            doc["latency"]["preprocessing_ms"] = self.latency.preprocessing_ms
        if self.latency.postprocessing_ms is not None:
            doc["latency"]["postprocessing_ms"] = self.latency.postprocessing_ms

        # Add error details
        if self.error:
            doc["error"] = {
                "type": self.error.type.value,
                "retryable": self.error.retryable,
                "retry_count": self.error.retry_count,
            }
            if self.error.code:
                doc["error"]["code"] = self.error.code
            if self.error.message:
                doc["error"]["message"] = self.error.message[:1000]  # Truncate

        # Add rate limit details
        if self.rate_limit.remaining_requests is not None:
            doc["rate_limit"]["remaining_requests"] = self.rate_limit.remaining_requests
        if self.rate_limit.remaining_tokens is not None:
            doc["rate_limit"]["remaining_tokens"] = self.rate_limit.remaining_tokens
        if self.rate_limit.reset_at:
            doc["rate_limit"]["reset_at"] = self.rate_limit.reset_at.isoformat()

        # Add cache details
        if self.cache.key:
            doc["cache"]["key"] = self.cache.key
        if self.cache.ttl_seconds is not None:
            doc["cache"]["ttl_seconds"] = self.cache.ttl_seconds

        # Add streaming details
        if self.streaming.first_chunk_ms is not None:
            doc["streaming"]["first_chunk_ms"] = self.streaming.first_chunk_ms
        if self.streaming.last_chunk_ms is not None:
            doc["streaming"]["last_chunk_ms"] = self.streaming.last_chunk_ms

        # Add context and infrastructure
        if self.context:
            doc["context"] = self.context
        if self.infrastructure:
            doc["infrastructure"] = self.infrastructure
        if self.metadata:
            doc["metadata"] = self.metadata

        return doc


class TechnicalMonitor:
    """
    Technical monitoring for AI systems.

    Tracks latency, throughput, errors, and other technical metrics
    for AI API calls across different providers.
    """

    def __init__(self, config: Config):
        """
        Initialize the technical monitor.

        Args:
            config: Configuration object
        """
        self.config = config
        self.tech_config = config.technical
        self._metrics_buffer: List[TechnicalMetric] = []
        self._buffer_lock = Lock()

        # Metrics aggregation for real-time analysis
        self._latency_window: Dict[str, List[float]] = defaultdict(list)
        self._error_counts: Dict[str, int] = defaultdict(int)
        self._request_counts: Dict[str, int] = defaultdict(int)
        self._window_start = time.time()
        self._window_duration = 60  # 1 minute windows

    def record_request(
        self,
        request_id: str,
        provider: str,
        model: str,
        latency_ms: float,
        tokens_input: int,
        tokens_output: int,
        status: RequestStatus = RequestStatus.SUCCESS,
        **kwargs
    ) -> TechnicalMetric:
        """
        Record a technical metric for an AI request.

        Args:
            request_id: Unique request identifier
            provider: AI provider name (openai, anthropic, etc.)
            model: Model name
            latency_ms: Total latency in milliseconds
            tokens_input: Number of input tokens
            tokens_output: Number of output tokens
            status: Request status
            **kwargs: Additional metric fields

        Returns:
            The recorded metric
        """
        # Calculate throughput
        tokens_total = tokens_input + tokens_output
        tokens_per_second = (tokens_total / (latency_ms / 1000)) if latency_ms > 0 else 0

        metric = TechnicalMetric(
            request_id=request_id,
            provider=provider,
            model=model,
            status=status,
            latency=LatencyMetrics(
                total_ms=latency_ms,
                time_to_first_token_ms=kwargs.get('ttft_ms'),
                inference_ms=kwargs.get('inference_ms'),
                network_ms=kwargs.get('network_ms'),
                queue_ms=kwargs.get('queue_ms'),
            ),
            throughput=ThroughputMetrics(
                tokens_per_second=tokens_per_second,
                concurrent_requests=kwargs.get('concurrent_requests', 0),
            ),
            tokens=TokenMetrics(
                input=tokens_input,
                output=tokens_output,
                total=tokens_total,
                cached=kwargs.get('tokens_cached', 0),
            ),
        )

        # Set optional fields
        if 'trace_id' in kwargs:
            metric.trace_id = kwargs['trace_id']
        if 'span_id' in kwargs:
            metric.span_id = kwargs['span_id']
        if 'model_version' in kwargs:
            metric.model_version = kwargs['model_version']
        if 'endpoint' in kwargs:
            metric.endpoint = kwargs['endpoint']
        if 'operation' in kwargs:
            metric.operation = kwargs['operation']
        if 'environment' in kwargs:
            metric.environment = kwargs['environment']
        if 'region' in kwargs:
            metric.region = kwargs['region']
        if 'status_code' in kwargs:
            metric.status_code = kwargs['status_code']

        # Set error info
        if 'error_type' in kwargs:
            metric.error = ErrorMetrics(
                type=kwargs['error_type'],
                code=kwargs.get('error_code'),
                message=kwargs.get('error_message'),
                retryable=kwargs.get('error_retryable', False),
                retry_count=kwargs.get('retry_count', 0),
            )

        # Set rate limit info
        if 'rate_limited' in kwargs:
            metric.rate_limit = RateLimitMetrics(
                limited=kwargs['rate_limited'],
                remaining_requests=kwargs.get('rate_limit_remaining_requests'),
                remaining_tokens=kwargs.get('rate_limit_remaining_tokens'),
            )

        # Set cache info
        if 'cache_hit' in kwargs:
            metric.cache = CacheMetrics(
                hit=kwargs['cache_hit'],
                key=kwargs.get('cache_key'),
                ttl_seconds=kwargs.get('cache_ttl'),
            )

        # Set streaming info
        if 'streaming' in kwargs:
            metric.streaming = StreamingMetrics(
                enabled=kwargs['streaming'],
                chunks_count=kwargs.get('chunks_count', 0),
                first_chunk_ms=kwargs.get('first_chunk_ms'),
                last_chunk_ms=kwargs.get('last_chunk_ms'),
            )

        # Set context
        for ctx_field in ['team', 'project', 'application', 'user_id', 'session_id']:
            if ctx_field in kwargs:
                metric.context[ctx_field] = kwargs[ctx_field]

        # Set infrastructure
        for infra_field in ['host', 'instance_type', 'availability_zone',
                           'container_id', 'pod_name']:
            if infra_field in kwargs:
                metric.infrastructure[infra_field] = kwargs[infra_field]

        # Add to buffer
        with self._buffer_lock:
            self._metrics_buffer.append(metric)

        # Update aggregations
        self._update_aggregations(metric)

        return metric

    def _update_aggregations(self, metric: TechnicalMetric) -> None:
        """Update real-time aggregations."""
        key = f"{metric.provider}:{metric.model}"

        # Rotate window if needed
        current_time = time.time()
        if current_time - self._window_start > self._window_duration:
            self._rotate_window()

        # Update latency window
        self._latency_window[key].append(metric.latency.total_ms)

        # Update counts
        self._request_counts[key] += 1
        if metric.status != RequestStatus.SUCCESS:
            self._error_counts[key] += 1

    def _rotate_window(self) -> None:
        """Rotate the aggregation window."""
        self._latency_window.clear()
        self._error_counts.clear()
        self._request_counts.clear()
        self._window_start = time.time()

    def get_buffered_metrics(self, clear: bool = True) -> List[TechnicalMetric]:
        """
        Get buffered metrics.

        Args:
            clear: Whether to clear the buffer

        Returns:
            List of buffered metrics
        """
        with self._buffer_lock:
            metrics = self._metrics_buffer.copy()
            if clear:
                self._metrics_buffer.clear()
        return metrics

    def get_latency_percentiles(
        self,
        provider: Optional[str] = None,
        model: Optional[str] = None
    ) -> Dict[str, float]:
        """
        Get latency percentiles for the current window.

        Args:
            provider: Filter by provider
            model: Filter by model

        Returns:
            Dictionary with p50, p95, p99 latencies
        """
        latencies = []

        for key, values in self._latency_window.items():
            if provider and not key.startswith(f"{provider}:"):
                continue
            if model and not key.endswith(f":{model}"):
                continue
            latencies.extend(values)

        if not latencies:
            return {"p50": 0, "p95": 0, "p99": 0}

        sorted_latencies = sorted(latencies)
        n = len(sorted_latencies)

        return {
            "p50": sorted_latencies[int(n * 0.50)] if n > 0 else 0,
            "p95": sorted_latencies[int(n * 0.95)] if n > 0 else 0,
            "p99": sorted_latencies[int(n * 0.99)] if n > 0 else 0,
            "min": min(sorted_latencies) if n > 0 else 0,
            "max": max(sorted_latencies) if n > 0 else 0,
            "avg": statistics.mean(sorted_latencies) if n > 0 else 0,
            "count": n,
        }

    def get_error_rate(
        self,
        provider: Optional[str] = None,
        model: Optional[str] = None
    ) -> float:
        """
        Get error rate for the current window.

        Args:
            provider: Filter by provider
            model: Filter by model

        Returns:
            Error rate as percentage
        """
        total_requests = 0
        total_errors = 0

        for key in self._request_counts:
            if provider and not key.startswith(f"{provider}:"):
                continue
            if model and not key.endswith(f":{model}"):
                continue

            total_requests += self._request_counts[key]
            total_errors += self._error_counts.get(key, 0)

        if total_requests == 0:
            return 0.0

        return (total_errors / total_requests) * 100

    def check_thresholds(self) -> List[Dict[str, Any]]:
        """
        Check if any metrics exceed configured thresholds.

        Returns:
            List of threshold violations
        """
        violations = []
        thresholds = self.tech_config.latency
        error_thresholds = self.tech_config.error_rate

        # Get current metrics
        percentiles = self.get_latency_percentiles()
        error_rate = self.get_error_rate()

        # Check latency thresholds
        if percentiles["p50"] > thresholds.p50_critical:
            violations.append({
                "type": "latency_p50_critical",
                "value": percentiles["p50"],
                "threshold": thresholds.p50_critical,
                "severity": "critical",
            })
        elif percentiles["p50"] > thresholds.p50_warning:
            violations.append({
                "type": "latency_p50_warning",
                "value": percentiles["p50"],
                "threshold": thresholds.p50_warning,
                "severity": "warning",
            })

        if percentiles["p95"] > thresholds.p95_critical:
            violations.append({
                "type": "latency_p95_critical",
                "value": percentiles["p95"],
                "threshold": thresholds.p95_critical,
                "severity": "critical",
            })
        elif percentiles["p95"] > thresholds.p95_warning:
            violations.append({
                "type": "latency_p95_warning",
                "value": percentiles["p95"],
                "threshold": thresholds.p95_warning,
                "severity": "warning",
            })

        if percentiles["p99"] > thresholds.p99_critical:
            violations.append({
                "type": "latency_p99_critical",
                "value": percentiles["p99"],
                "threshold": thresholds.p99_critical,
                "severity": "critical",
            })
        elif percentiles["p99"] > thresholds.p99_warning:
            violations.append({
                "type": "latency_p99_warning",
                "value": percentiles["p99"],
                "threshold": thresholds.p99_warning,
                "severity": "warning",
            })

        # Check error rate thresholds
        if error_rate > error_thresholds.critical:
            violations.append({
                "type": "error_rate_critical",
                "value": error_rate,
                "threshold": error_thresholds.critical,
                "severity": "critical",
            })
        elif error_rate > error_thresholds.warning:
            violations.append({
                "type": "error_rate_warning",
                "value": error_rate,
                "threshold": error_thresholds.warning,
                "severity": "warning",
            })

        return violations

    def get_summary(self) -> Dict[str, Any]:
        """
        Get a summary of current technical metrics.

        Returns:
            Summary dictionary
        """
        return {
            "latency": self.get_latency_percentiles(),
            "error_rate": self.get_error_rate(),
            "violations": self.check_thresholds(),
            "window_duration_seconds": self._window_duration,
            "window_age_seconds": time.time() - self._window_start,
            "buffered_metrics": len(self._metrics_buffer),
        }


class RequestTracer:
    """
    Context manager for tracing AI requests.

    Automatically captures timing and metrics for AI API calls.
    """

    def __init__(
        self,
        monitor: TechnicalMonitor,
        request_id: str,
        provider: str,
        model: str,
        **kwargs
    ):
        """
        Initialize the request tracer.

        Args:
            monitor: Technical monitor instance
            request_id: Unique request identifier
            provider: AI provider name
            model: Model name
            **kwargs: Additional metric fields
        """
        self.monitor = monitor
        self.request_id = request_id
        self.provider = provider
        self.model = model
        self.kwargs = kwargs

        self._start_time: Optional[float] = None
        self._first_token_time: Optional[float] = None
        self._tokens_input = 0
        self._tokens_output = 0
        self._status = RequestStatus.SUCCESS
        self._chunks: List[float] = []

    def __enter__(self) -> "RequestTracer":
        """Start tracing."""
        self._start_time = time.time()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        """End tracing and record metrics."""
        end_time = time.time()
        latency_ms = (end_time - self._start_time) * 1000

        if exc_type is not None:
            self._status = RequestStatus.ERROR
            self.kwargs['error_type'] = ErrorType.UNKNOWN
            self.kwargs['error_message'] = str(exc_val)

        ttft_ms = None
        if self._first_token_time:
            ttft_ms = (self._first_token_time - self._start_time) * 1000

        # Add streaming info
        if self._chunks:
            self.kwargs['streaming'] = True
            self.kwargs['chunks_count'] = len(self._chunks)
            self.kwargs['first_chunk_ms'] = ttft_ms
            self.kwargs['last_chunk_ms'] = (self._chunks[-1] - self._start_time) * 1000

        self.monitor.record_request(
            request_id=self.request_id,
            provider=self.provider,
            model=self.model,
            latency_ms=latency_ms,
            tokens_input=self._tokens_input,
            tokens_output=self._tokens_output,
            status=self._status,
            ttft_ms=ttft_ms,
            **self.kwargs
        )

    def set_tokens(self, input_tokens: int, output_tokens: int) -> None:
        """Set token counts."""
        self._tokens_input = input_tokens
        self._tokens_output = output_tokens

    def record_first_token(self) -> None:
        """Record time of first token received."""
        if self._first_token_time is None:
            self._first_token_time = time.time()

    def record_chunk(self) -> None:
        """Record a streaming chunk."""
        chunk_time = time.time()
        if not self._chunks:
            self._first_token_time = chunk_time
        self._chunks.append(chunk_time)

    def set_status(self, status: RequestStatus) -> None:
        """Set the request status."""
        self._status = status

    def set_error(
        self,
        error_type: ErrorType,
        code: Optional[str] = None,
        message: Optional[str] = None,
        retryable: bool = False
    ) -> None:
        """Set error information."""
        self._status = RequestStatus.ERROR
        self.kwargs['error_type'] = error_type
        self.kwargs['error_code'] = code
        self.kwargs['error_message'] = message
        self.kwargs['error_retryable'] = retryable
