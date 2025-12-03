"""
Metrics Collector Module
========================

Central collector that aggregates metrics from all monitors
and sends them to Elasticsearch in batches.
"""

import logging
import threading
import time
import uuid
from datetime import datetime, timezone
from typing import Dict, List, Optional, Any, Callable
from dataclasses import dataclass
from queue import Queue, Empty
from concurrent.futures import ThreadPoolExecutor

from .config import Config
from .elasticsearch_client import AIMonitoringClient
from .technical_monitor import TechnicalMonitor, TechnicalMetric, RequestStatus
from .cognitive_monitor import CognitiveMonitor, CognitiveMetric
from .finops_monitor import FinOpsMonitor, FinOpsMetric
from .devops_monitor import DevOpsMonitor, DevOpsMetric
from .compliance_monitor import ComplianceMonitor, ComplianceMetric

logger = logging.getLogger(__name__)


@dataclass
class AIRequest:
    """Represents an AI request for comprehensive monitoring."""
    request_id: str
    provider: str
    model: str
    prompt: str
    response: str
    input_tokens: int
    output_tokens: int
    latency_ms: float
    status: str = "success"
    trace_id: Optional[str] = None
    environment: str = "production"
    team: Optional[str] = None
    project: Optional[str] = None
    application: Optional[str] = None
    user_id: Optional[str] = None
    metadata: Dict[str, Any] = None

    def __post_init__(self):
        if self.metadata is None:
            self.metadata = {}


class MetricsCollector:
    """
    Central metrics collector that orchestrates all monitoring modules.

    Features:
    - Unified API for recording AI requests
    - Automatic batching and flushing to Elasticsearch
    - Background thread for periodic flushing
    - Dead letter queue for failed documents
    - Hooks for custom processing
    """

    def __init__(self, config: Config, es_client: Optional[AIMonitoringClient] = None):
        """
        Initialize the metrics collector.

        Args:
            config: Configuration object
            es_client: Optional Elasticsearch client (created if not provided)
        """
        self.config = config
        self.collection_config = config.collection

        # Initialize ES client
        self.es_client = es_client or AIMonitoringClient(config)

        # Initialize monitors
        self.technical_monitor = TechnicalMonitor(config)
        self.cognitive_monitor = CognitiveMonitor(config)
        self.finops_monitor = FinOpsMonitor(config)
        self.devops_monitor = DevOpsMonitor(config)
        self.compliance_monitor = ComplianceMonitor(config)

        # Batching queues
        self._technical_queue: Queue = Queue()
        self._cognitive_queue: Queue = Queue()
        self._finops_queue: Queue = Queue()
        self._devops_queue: Queue = Queue()
        self._compliance_queue: Queue = Queue()

        # Dead letter queue
        self._dead_letter_queue: Queue = Queue()

        # Background processing
        self._running = False
        self._flush_thread: Optional[threading.Thread] = None
        self._executor = ThreadPoolExecutor(max_workers=4)

        # Hooks
        self._pre_process_hooks: List[Callable[[AIRequest], AIRequest]] = []
        self._post_process_hooks: List[Callable[[AIRequest, Dict[str, Any]], None]] = []

        # Statistics
        self._stats = {
            "total_requests": 0,
            "successful_flushes": 0,
            "failed_flushes": 0,
            "dead_letter_count": 0,
        }

    def start(self) -> None:
        """Start the background flush thread."""
        if self._running:
            return

        self._running = True
        self._flush_thread = threading.Thread(
            target=self._flush_loop,
            daemon=True,
            name="metrics-flush"
        )
        self._flush_thread.start()
        logger.info("Metrics collector started")

    def stop(self) -> None:
        """Stop the background flush thread and flush remaining metrics."""
        if not self._running:
            return

        self._running = False

        # Final flush
        self.flush()

        if self._flush_thread:
            self._flush_thread.join(timeout=10)

        self._executor.shutdown(wait=True)
        logger.info("Metrics collector stopped")

    def _flush_loop(self) -> None:
        """Background loop for periodic flushing."""
        while self._running:
            try:
                time.sleep(self.collection_config.flush_interval_seconds)
                self.flush()
            except Exception as e:
                logger.error(f"Error in flush loop: {e}")

    def add_pre_process_hook(self, hook: Callable[[AIRequest], AIRequest]) -> None:
        """Add a pre-processing hook."""
        self._pre_process_hooks.append(hook)

    def add_post_process_hook(
        self,
        hook: Callable[[AIRequest, Dict[str, Any]], None]
    ) -> None:
        """Add a post-processing hook."""
        self._post_process_hooks.append(hook)

    def record(self, request: AIRequest) -> Dict[str, Any]:
        """
        Record an AI request across all monitoring dimensions.

        Args:
            request: AI request to record

        Returns:
            Dictionary with metrics from all monitors
        """
        self._stats["total_requests"] += 1

        # Run pre-process hooks
        for hook in self._pre_process_hooks:
            try:
                request = hook(request)
            except Exception as e:
                logger.warning(f"Pre-process hook failed: {e}")

        results = {}

        # Record technical metrics
        if self.config.technical.enabled:
            technical_metric = self.technical_monitor.record_request(
                request_id=request.request_id,
                provider=request.provider,
                model=request.model,
                latency_ms=request.latency_ms,
                tokens_input=request.input_tokens,
                tokens_output=request.output_tokens,
                status=RequestStatus.SUCCESS if request.status == "success" else RequestStatus.ERROR,
                trace_id=request.trace_id,
                environment=request.environment,
                team=request.team,
                project=request.project,
                application=request.application,
                user_id=request.user_id,
            )
            self._technical_queue.put(technical_metric)
            results["technical"] = technical_metric

        # Record cognitive metrics
        if self.config.cognitive.enabled:
            cognitive_metric = self.cognitive_monitor.analyze_request(
                request_id=request.request_id,
                provider=request.provider,
                model=request.model,
                prompt=request.prompt,
                response=request.response,
                trace_id=request.trace_id,
                environment=request.environment,
                team=request.team,
                project=request.project,
                application=request.application,
            )
            self._cognitive_queue.put(cognitive_metric)
            results["cognitive"] = cognitive_metric

        # Record FinOps metrics
        if self.config.finops.enabled:
            finops_metric = self.finops_monitor.record_usage(
                request_id=request.request_id,
                provider=request.provider,
                model=request.model,
                input_tokens=request.input_tokens,
                output_tokens=request.output_tokens,
                team=request.team,
                project=request.project,
                environment=request.environment,
                application=request.application,
                user_id=request.user_id,
            )
            self._finops_queue.put(finops_metric)
            results["finops"] = finops_metric

        # Record compliance metrics
        if self.config.compliance.enabled:
            compliance_metric = self.compliance_monitor.record_ai_request(
                request_id=request.request_id,
                prompt=request.prompt,
                response=request.response,
                provider=request.provider,
                model=request.model,
                actor_id=request.user_id or "anonymous",
                trace_id=request.trace_id,
                environment=request.environment,
            )
            self._compliance_queue.put(compliance_metric)
            results["compliance"] = compliance_metric

        # Run post-process hooks
        for hook in self._post_process_hooks:
            try:
                hook(request, results)
            except Exception as e:
                logger.warning(f"Post-process hook failed: {e}")

        return results

    def record_simple(
        self,
        provider: str,
        model: str,
        prompt: str,
        response: str,
        input_tokens: int,
        output_tokens: int,
        latency_ms: float,
        **kwargs
    ) -> Dict[str, Any]:
        """
        Simplified recording interface.

        Args:
            provider: AI provider name
            model: Model name
            prompt: Input prompt
            response: Generated response
            input_tokens: Number of input tokens
            output_tokens: Number of output tokens
            latency_ms: Request latency in milliseconds
            **kwargs: Additional fields

        Returns:
            Dictionary with metrics from all monitors
        """
        request = AIRequest(
            request_id=kwargs.get('request_id', str(uuid.uuid4())),
            provider=provider,
            model=model,
            prompt=prompt,
            response=response,
            input_tokens=input_tokens,
            output_tokens=output_tokens,
            latency_ms=latency_ms,
            status=kwargs.get('status', 'success'),
            trace_id=kwargs.get('trace_id'),
            environment=kwargs.get('environment', 'production'),
            team=kwargs.get('team'),
            project=kwargs.get('project'),
            application=kwargs.get('application'),
            user_id=kwargs.get('user_id'),
            metadata=kwargs.get('metadata'),
        )

        return self.record(request)

    def flush(self) -> Dict[str, Any]:
        """
        Flush all buffered metrics to Elasticsearch.

        Returns:
            Flush statistics
        """
        results = {
            "technical": self._flush_queue(
                self._technical_queue,
                f"{self.config.technical.index_prefix}"
            ),
            "cognitive": self._flush_queue(
                self._cognitive_queue,
                f"{self.config.cognitive.index_prefix}"
            ),
            "finops": self._flush_queue(
                self._finops_queue,
                f"{self.config.finops.index_prefix}"
            ),
            "devops": self._flush_queue(
                self._devops_queue,
                f"{self.config.devops.index_prefix}"
            ),
            "compliance": self._flush_queue(
                self._compliance_queue,
                f"{self.config.compliance.index_prefix}"
            ),
        }

        # Log summary
        total_flushed = sum(r.get("indexed", 0) for r in results.values())
        total_errors = sum(r.get("errors", 0) for r in results.values())

        if total_flushed > 0 or total_errors > 0:
            logger.info(f"Flushed {total_flushed} metrics, {total_errors} errors")

        return results

    def _flush_queue(self, queue: Queue, index_prefix: str) -> Dict[str, Any]:
        """Flush a specific queue to Elasticsearch."""
        documents = []

        # Drain queue up to batch size
        while len(documents) < self.collection_config.batch_size:
            try:
                metric = queue.get_nowait()
                documents.append(metric.to_dict())
            except Empty:
                break

        if not documents:
            return {"indexed": 0, "errors": 0}

        # Try to index
        try:
            result = self.es_client.bulk_index(index_prefix, documents)
            self._stats["successful_flushes"] += 1
            return result

        except Exception as e:
            logger.error(f"Failed to flush to {index_prefix}: {e}")
            self._stats["failed_flushes"] += 1

            # Handle retry
            if self.collection_config.retry_on_failure:
                for doc in documents:
                    self._dead_letter_queue.put({
                        "index": index_prefix,
                        "document": doc,
                        "error": str(e),
                        "timestamp": datetime.now(timezone.utc).isoformat(),
                    })
                self._stats["dead_letter_count"] += len(documents)

            return {"indexed": 0, "errors": len(documents)}

    def record_health_check(self, **kwargs) -> DevOpsMetric:
        """Record a health check (convenience method)."""
        from .devops_monitor import HealthStatus
        return self.devops_monitor.record_health_check(
            status=kwargs.get('status', HealthStatus.HEALTHY),
            **kwargs
        )

    def record_deployment(self, **kwargs) -> DevOpsMetric:
        """Record a deployment event (convenience method)."""
        return self.devops_monitor.record_deployment(**kwargs)

    def get_summary(self) -> Dict[str, Any]:
        """
        Get a summary of all monitoring metrics.

        Returns:
            Comprehensive summary across all dimensions
        """
        return {
            "technical": self.technical_monitor.get_summary(),
            "cognitive": self.cognitive_monitor.get_summary(),
            "finops": {
                "cost_summary": self.finops_monitor.get_cost_summary(),
                "roi_summary": self.finops_monitor.get_roi_summary(),
                "budget_alerts": self.finops_monitor.check_budget_alerts(),
                "recommendations": self.finops_monitor.get_optimization_recommendations(),
            },
            "devops": self.devops_monitor.get_system_status(),
            "compliance": self.compliance_monitor.get_compliance_summary(),
            "collector": {
                "stats": self._stats,
                "queue_sizes": {
                    "technical": self._technical_queue.qsize(),
                    "cognitive": self._cognitive_queue.qsize(),
                    "finops": self._finops_queue.qsize(),
                    "devops": self._devops_queue.qsize(),
                    "compliance": self._compliance_queue.qsize(),
                    "dead_letter": self._dead_letter_queue.qsize(),
                },
            },
        }

    def check_alerts(self) -> List[Dict[str, Any]]:
        """
        Check for alerts across all monitors.

        Returns:
            List of active alerts
        """
        alerts = []

        # Technical alerts
        violations = self.technical_monitor.check_thresholds()
        for v in violations:
            alerts.append({
                "category": "technical",
                "type": v["type"],
                "severity": v["severity"],
                "value": v["value"],
                "threshold": v["threshold"],
            })

        # FinOps alerts
        budget_alerts = self.finops_monitor.check_budget_alerts()
        for alert in budget_alerts:
            alerts.append({
                "category": "finops",
                **alert
            })

        # Compliance alerts
        violations = self.compliance_monitor.check_compliance_violations()
        for v in violations:
            alerts.append({
                "category": "compliance",
                **v
            })

        return alerts

    def get_dead_letter_items(self, limit: int = 100) -> List[Dict[str, Any]]:
        """Get items from the dead letter queue."""
        items = []
        while len(items) < limit:
            try:
                item = self._dead_letter_queue.get_nowait()
                items.append(item)
            except Empty:
                break
        return items

    def retry_dead_letter(self) -> Dict[str, Any]:
        """Retry items in the dead letter queue."""
        items = self.get_dead_letter_items()
        if not items:
            return {"retried": 0, "success": 0, "failed": 0}

        success = 0
        failed = 0

        for item in items:
            try:
                self.es_client.index_document(
                    index=item["index"],
                    document=item["document"]
                )
                success += 1
            except Exception:
                failed += 1
                self._dead_letter_queue.put(item)

        return {
            "retried": len(items),
            "success": success,
            "failed": failed,
        }


class MonitoringContext:
    """
    Context manager for monitoring AI requests.

    Usage:
        with MonitoringContext(collector, provider="openai", model="gpt-4") as ctx:
            response = call_ai_api(prompt)
            ctx.set_response(response, tokens_in, tokens_out)
    """

    def __init__(
        self,
        collector: MetricsCollector,
        provider: str,
        model: str,
        **kwargs
    ):
        """
        Initialize the monitoring context.

        Args:
            collector: Metrics collector instance
            provider: AI provider name
            model: Model name
            **kwargs: Additional context fields
        """
        self.collector = collector
        self.provider = provider
        self.model = model
        self.kwargs = kwargs

        self.request_id = kwargs.get('request_id', str(uuid.uuid4()))
        self._start_time: Optional[float] = None
        self._prompt: Optional[str] = None
        self._response: Optional[str] = None
        self._input_tokens: int = 0
        self._output_tokens: int = 0
        self._status: str = "success"

    def __enter__(self) -> "MonitoringContext":
        """Start monitoring."""
        self._start_time = time.time()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        """End monitoring and record metrics."""
        end_time = time.time()
        latency_ms = (end_time - self._start_time) * 1000

        if exc_type is not None:
            self._status = "error"

        if self._prompt and self._response:
            self.collector.record_simple(
                provider=self.provider,
                model=self.model,
                prompt=self._prompt,
                response=self._response,
                input_tokens=self._input_tokens,
                output_tokens=self._output_tokens,
                latency_ms=latency_ms,
                status=self._status,
                request_id=self.request_id,
                **self.kwargs
            )

    def set_prompt(self, prompt: str) -> None:
        """Set the input prompt."""
        self._prompt = prompt

    def set_response(
        self,
        response: str,
        input_tokens: int,
        output_tokens: int
    ) -> None:
        """Set the response and token counts."""
        self._response = response
        self._input_tokens = input_tokens
        self._output_tokens = output_tokens

    def set_error(self) -> None:
        """Mark the request as failed."""
        self._status = "error"
