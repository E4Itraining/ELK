"""
DevOps Monitoring Module
========================

Monitors DevOps aspects of AI systems including:
- Deployment tracking
- Scaling events
- Health checks
- Infrastructure metrics (CPU, Memory, GPU)
- Availability and SLA
- Circuit breakers and incidents
"""

import logging
import platform
import psutil
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field
from enum import Enum
from collections import defaultdict
from threading import Lock

from .config import Config, DevOpsConfig

logger = logging.getLogger(__name__)


class EventType(Enum):
    """DevOps event types."""
    DEPLOYMENT = "deployment"
    SCALING = "scaling"
    HEALTH_CHECK = "health_check"
    INCIDENT = "incident"
    RESOURCE_ALERT = "resource_alert"
    CIRCUIT_BREAKER = "circuit_breaker"


class DeploymentStatus(Enum):
    """Deployment status."""
    PENDING = "pending"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    FAILED = "failed"
    ROLLED_BACK = "rolled_back"


class DeploymentStrategy(Enum):
    """Deployment strategy."""
    ROLLING = "rolling"
    BLUE_GREEN = "blue_green"
    CANARY = "canary"
    RECREATE = "recreate"


class HealthStatus(Enum):
    """Health status."""
    HEALTHY = "healthy"
    DEGRADED = "degraded"
    UNHEALTHY = "unhealthy"
    UNKNOWN = "unknown"


class ScalingEventType(Enum):
    """Scaling event type."""
    SCALE_UP = "scale_up"
    SCALE_DOWN = "scale_down"
    SCALE_OUT = "scale_out"
    SCALE_IN = "scale_in"


class ScalingTrigger(Enum):
    """Scaling trigger."""
    CPU = "cpu"
    MEMORY = "memory"
    LATENCY = "latency"
    QUEUE_DEPTH = "queue_depth"
    REQUESTS_PER_SECOND = "rps"
    MANUAL = "manual"
    SCHEDULED = "scheduled"


class CircuitBreakerState(Enum):
    """Circuit breaker state."""
    CLOSED = "closed"
    OPEN = "open"
    HALF_OPEN = "half_open"


class IncidentSeverity(Enum):
    """Incident severity."""
    SEV1 = "sev1"  # Critical
    SEV2 = "sev2"  # Major
    SEV3 = "sev3"  # Minor
    SEV4 = "sev4"  # Low


class IncidentStatus(Enum):
    """Incident status."""
    DETECTED = "detected"
    INVESTIGATING = "investigating"
    IDENTIFIED = "identified"
    MITIGATING = "mitigating"
    RESOLVED = "resolved"


@dataclass
class DeploymentInfo:
    """Deployment information."""
    id: str = ""
    version: str = ""
    previous_version: Optional[str] = None
    model: Optional[str] = None
    model_version: Optional[str] = None
    status: DeploymentStatus = DeploymentStatus.PENDING
    strategy: DeploymentStrategy = DeploymentStrategy.ROLLING
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    duration_seconds: float = 0.0
    triggered_by: str = ""
    commit_sha: Optional[str] = None
    rollback: bool = False
    rollback_reason: Optional[str] = None


@dataclass
class CanaryInfo:
    """Canary deployment information."""
    enabled: bool = False
    traffic_percentage: float = 0.0
    success_rate: float = 0.0
    latency_p50: float = 0.0
    latency_p95: float = 0.0
    error_rate: float = 0.0
    promoted: bool = False
    promotion_criteria_met: bool = False


@dataclass
class ScalingInfo:
    """Scaling event information."""
    event_type: ScalingEventType = ScalingEventType.SCALE_UP
    current_replicas: int = 0
    desired_replicas: int = 0
    min_replicas: int = 0
    max_replicas: int = 0
    trigger: ScalingTrigger = ScalingTrigger.CPU
    metric_value: float = 0.0
    metric_threshold: float = 0.0
    cooldown_remaining: int = 0


@dataclass
class HealthInfo:
    """Health check information."""
    status: HealthStatus = HealthStatus.UNKNOWN
    liveness_check: bool = True
    readiness_check: bool = True
    startup_check: bool = True
    consecutive_failures: int = 0
    last_success: Optional[datetime] = None
    response_time_ms: float = 0.0


@dataclass
class AvailabilityInfo:
    """Availability metrics."""
    uptime_percentage: float = 100.0
    downtime_seconds: int = 0
    sla_target: float = 99.9
    sla_met: bool = True
    mttr_seconds: int = 0  # Mean Time To Recovery
    mtbf_seconds: int = 0  # Mean Time Between Failures
    incident_count: int = 0


@dataclass
class CPUMetrics:
    """CPU metrics."""
    usage_percent: float = 0.0
    limit_cores: float = 0.0
    request_cores: float = 0.0
    throttled_seconds: float = 0.0


@dataclass
class MemoryMetrics:
    """Memory metrics."""
    usage_bytes: int = 0
    usage_percent: float = 0.0
    limit_bytes: int = 0
    request_bytes: int = 0
    oom_killed: bool = False


@dataclass
class GPUMetrics:
    """GPU metrics."""
    usage_percent: float = 0.0
    memory_usage_bytes: int = 0
    memory_total_bytes: int = 0
    temperature_celsius: float = 0.0
    power_watts: float = 0.0
    gpu_type: str = ""
    cuda_version: str = ""


@dataclass
class NetworkMetrics:
    """Network metrics."""
    rx_bytes: int = 0
    tx_bytes: int = 0
    rx_errors: int = 0
    tx_errors: int = 0
    connections_active: int = 0


@dataclass
class DiskMetrics:
    """Disk metrics."""
    usage_bytes: int = 0
    usage_percent: float = 0.0
    iops_read: int = 0
    iops_write: int = 0


@dataclass
class ResourceMetrics:
    """Complete resource metrics."""
    cpu: CPUMetrics = field(default_factory=CPUMetrics)
    memory: MemoryMetrics = field(default_factory=MemoryMetrics)
    gpu: Optional[GPUMetrics] = None
    network: NetworkMetrics = field(default_factory=NetworkMetrics)
    disk: DiskMetrics = field(default_factory=DiskMetrics)


@dataclass
class InfrastructureInfo:
    """Infrastructure information."""
    instance_id: str = ""
    instance_type: str = ""
    availability_zone: str = ""
    cluster_name: str = ""
    namespace: str = ""
    pod_name: str = ""
    container_id: str = ""
    node_name: str = ""


@dataclass
class QueueMetrics:
    """Queue metrics."""
    name: str = ""
    depth: int = 0
    oldest_message_age_seconds: int = 0
    processing_rate: float = 0.0
    dead_letter_count: int = 0


@dataclass
class CircuitBreakerInfo:
    """Circuit breaker information."""
    name: str = ""
    state: CircuitBreakerState = CircuitBreakerState.CLOSED
    failure_count: int = 0
    success_count: int = 0
    last_failure: Optional[datetime] = None
    reset_timeout_seconds: int = 0


@dataclass
class IncidentInfo:
    """Incident information."""
    id: str = ""
    severity: IncidentSeverity = IncidentSeverity.SEV3
    status: IncidentStatus = IncidentStatus.DETECTED
    started_at: Optional[datetime] = None
    resolved_at: Optional[datetime] = None
    duration_seconds: int = 0
    root_cause: str = ""
    affected_services: List[str] = field(default_factory=list)
    impact_users: int = 0


@dataclass
class DevOpsMetric:
    """Complete DevOps metric."""
    event_type: EventType = EventType.HEALTH_CHECK
    environment: str = "production"
    region: str = ""
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    deployment: Optional[DeploymentInfo] = None
    canary: Optional[CanaryInfo] = None
    scaling: Optional[ScalingInfo] = None
    health: HealthInfo = field(default_factory=HealthInfo)
    availability: AvailabilityInfo = field(default_factory=AvailabilityInfo)
    infrastructure: InfrastructureInfo = field(default_factory=InfrastructureInfo)
    resources: ResourceMetrics = field(default_factory=ResourceMetrics)
    queue: Optional[QueueMetrics] = None
    circuit_breaker: Optional[CircuitBreakerInfo] = None
    incident: Optional[IncidentInfo] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for Elasticsearch indexing."""
        doc = {
            "@timestamp": self.timestamp.isoformat(),
            "event_type": self.event_type.value,
            "environment": self.environment,
            "region": self.region,
            "health": {
                "status": self.health.status.value,
                "liveness_check": self.health.liveness_check,
                "readiness_check": self.health.readiness_check,
                "startup_check": self.health.startup_check,
                "consecutive_failures": self.health.consecutive_failures,
                "response_time_ms": self.health.response_time_ms,
            },
            "availability": {
                "uptime_percentage": self.availability.uptime_percentage,
                "downtime_seconds": self.availability.downtime_seconds,
                "sla_target": self.availability.sla_target,
                "sla_met": self.availability.sla_met,
                "mttr_seconds": self.availability.mttr_seconds,
                "mtbf_seconds": self.availability.mtbf_seconds,
                "incident_count": self.availability.incident_count,
            },
            "infrastructure": {
                "instance_id": self.infrastructure.instance_id,
                "instance_type": self.infrastructure.instance_type,
                "availability_zone": self.infrastructure.availability_zone,
                "cluster_name": self.infrastructure.cluster_name,
                "namespace": self.infrastructure.namespace,
                "pod_name": self.infrastructure.pod_name,
                "container_id": self.infrastructure.container_id,
                "node_name": self.infrastructure.node_name,
            },
            "resources": {
                "cpu": {
                    "usage_percent": self.resources.cpu.usage_percent,
                    "limit_cores": self.resources.cpu.limit_cores,
                    "request_cores": self.resources.cpu.request_cores,
                    "throttled_seconds": self.resources.cpu.throttled_seconds,
                },
                "memory": {
                    "usage_bytes": self.resources.memory.usage_bytes,
                    "usage_percent": self.resources.memory.usage_percent,
                    "limit_bytes": self.resources.memory.limit_bytes,
                    "request_bytes": self.resources.memory.request_bytes,
                    "oom_killed": self.resources.memory.oom_killed,
                },
                "network": {
                    "rx_bytes": self.resources.network.rx_bytes,
                    "tx_bytes": self.resources.network.tx_bytes,
                    "rx_errors": self.resources.network.rx_errors,
                    "tx_errors": self.resources.network.tx_errors,
                    "connections_active": self.resources.network.connections_active,
                },
                "disk": {
                    "usage_bytes": self.resources.disk.usage_bytes,
                    "usage_percent": self.resources.disk.usage_percent,
                    "iops_read": self.resources.disk.iops_read,
                    "iops_write": self.resources.disk.iops_write,
                },
            },
        }

        # Add last success time
        if self.health.last_success:
            doc["health"]["last_success"] = self.health.last_success.isoformat()

        # Add GPU metrics
        if self.resources.gpu:
            doc["resources"]["gpu"] = {
                "usage_percent": self.resources.gpu.usage_percent,
                "memory_usage_bytes": self.resources.gpu.memory_usage_bytes,
                "memory_total_bytes": self.resources.gpu.memory_total_bytes,
                "temperature_celsius": self.resources.gpu.temperature_celsius,
                "power_watts": self.resources.gpu.power_watts,
                "gpu_type": self.resources.gpu.gpu_type,
                "cuda_version": self.resources.gpu.cuda_version,
            }

        # Add deployment info
        if self.deployment:
            doc["deployment"] = {
                "id": self.deployment.id,
                "version": self.deployment.version,
                "status": self.deployment.status.value,
                "strategy": self.deployment.strategy.value,
                "duration_seconds": self.deployment.duration_seconds,
                "triggered_by": self.deployment.triggered_by,
                "rollback": self.deployment.rollback,
            }
            if self.deployment.previous_version:
                doc["deployment"]["previous_version"] = self.deployment.previous_version
            if self.deployment.model:
                doc["deployment"]["model"] = self.deployment.model
            if self.deployment.model_version:
                doc["deployment"]["model_version"] = self.deployment.model_version
            if self.deployment.started_at:
                doc["deployment"]["started_at"] = self.deployment.started_at.isoformat()
            if self.deployment.completed_at:
                doc["deployment"]["completed_at"] = self.deployment.completed_at.isoformat()
            if self.deployment.commit_sha:
                doc["deployment"]["commit_sha"] = self.deployment.commit_sha
            if self.deployment.rollback_reason:
                doc["deployment"]["rollback_reason"] = self.deployment.rollback_reason

        # Add canary info
        if self.canary:
            doc["canary"] = {
                "enabled": self.canary.enabled,
                "traffic_percentage": self.canary.traffic_percentage,
                "success_rate": self.canary.success_rate,
                "latency_p50": self.canary.latency_p50,
                "latency_p95": self.canary.latency_p95,
                "error_rate": self.canary.error_rate,
                "promoted": self.canary.promoted,
                "promotion_criteria_met": self.canary.promotion_criteria_met,
            }

        # Add scaling info
        if self.scaling:
            doc["scaling"] = {
                "event_type": self.scaling.event_type.value,
                "current_replicas": self.scaling.current_replicas,
                "desired_replicas": self.scaling.desired_replicas,
                "min_replicas": self.scaling.min_replicas,
                "max_replicas": self.scaling.max_replicas,
                "trigger": self.scaling.trigger.value,
                "metric_value": self.scaling.metric_value,
                "metric_threshold": self.scaling.metric_threshold,
                "cooldown_remaining": self.scaling.cooldown_remaining,
            }

        # Add queue info
        if self.queue:
            doc["queue"] = {
                "name": self.queue.name,
                "depth": self.queue.depth,
                "oldest_message_age_seconds": self.queue.oldest_message_age_seconds,
                "processing_rate": self.queue.processing_rate,
                "dead_letter_count": self.queue.dead_letter_count,
            }

        # Add circuit breaker info
        if self.circuit_breaker:
            doc["circuit_breaker"] = {
                "name": self.circuit_breaker.name,
                "state": self.circuit_breaker.state.value,
                "failure_count": self.circuit_breaker.failure_count,
                "success_count": self.circuit_breaker.success_count,
                "reset_timeout_seconds": self.circuit_breaker.reset_timeout_seconds,
            }
            if self.circuit_breaker.last_failure:
                doc["circuit_breaker"]["last_failure"] = self.circuit_breaker.last_failure.isoformat()

        # Add incident info
        if self.incident:
            doc["incident"] = {
                "id": self.incident.id,
                "severity": self.incident.severity.value,
                "status": self.incident.status.value,
                "duration_seconds": self.incident.duration_seconds,
                "root_cause": self.incident.root_cause,
                "affected_services": self.incident.affected_services,
                "impact_users": self.incident.impact_users,
            }
            if self.incident.started_at:
                doc["incident"]["started_at"] = self.incident.started_at.isoformat()
            if self.incident.resolved_at:
                doc["incident"]["resolved_at"] = self.incident.resolved_at.isoformat()

        # Add metadata
        if self.metadata:
            doc["metadata"] = self.metadata

        return doc


class DevOpsMonitor:
    """
    DevOps monitoring for AI systems.

    Tracks deployments, scaling, health, and infrastructure metrics.
    """

    def __init__(self, config: Config):
        """
        Initialize the DevOps monitor.

        Args:
            config: Configuration object
        """
        self.config = config
        self.devops_config = config.devops
        self._metrics_buffer: List[DevOpsMetric] = []
        self._buffer_lock = Lock()

        # State tracking
        self._current_deployments: Dict[str, DeploymentInfo] = {}
        self._circuit_breakers: Dict[str, CircuitBreakerInfo] = {}
        self._active_incidents: Dict[str, IncidentInfo] = {}
        self._health_history: List[HealthInfo] = []

        # Availability tracking
        self._uptime_start = datetime.now(timezone.utc)
        self._total_downtime = timedelta()
        self._incident_count = 0

    def collect_resource_metrics(self) -> ResourceMetrics:
        """
        Collect current resource metrics from the system.

        Returns:
            Resource metrics
        """
        resources = ResourceMetrics()

        try:
            # CPU metrics
            resources.cpu = CPUMetrics(
                usage_percent=psutil.cpu_percent(interval=0.1),
                limit_cores=float(psutil.cpu_count()),
                request_cores=float(psutil.cpu_count()),
            )

            # Memory metrics
            mem = psutil.virtual_memory()
            resources.memory = MemoryMetrics(
                usage_bytes=mem.used,
                usage_percent=mem.percent,
                limit_bytes=mem.total,
                request_bytes=mem.total,
            )

            # Disk metrics
            disk = psutil.disk_usage('/')
            resources.disk = DiskMetrics(
                usage_bytes=disk.used,
                usage_percent=disk.percent,
            )

            # Network metrics
            net = psutil.net_io_counters()
            resources.network = NetworkMetrics(
                rx_bytes=net.bytes_recv,
                tx_bytes=net.bytes_sent,
                rx_errors=net.errin,
                tx_errors=net.errout,
            )

        except Exception as e:
            logger.warning(f"Failed to collect resource metrics: {e}")

        return resources

    def record_health_check(
        self,
        status: HealthStatus,
        liveness: bool = True,
        readiness: bool = True,
        response_time_ms: float = 0.0,
        **kwargs
    ) -> DevOpsMetric:
        """
        Record a health check result.

        Args:
            status: Health status
            liveness: Liveness check result
            readiness: Readiness check result
            response_time_ms: Response time in milliseconds
            **kwargs: Additional fields

        Returns:
            The recorded metric
        """
        # Update health history
        health = HealthInfo(
            status=status,
            liveness_check=liveness,
            readiness_check=readiness,
            response_time_ms=response_time_ms,
        )

        if status == HealthStatus.HEALTHY:
            health.last_success = datetime.now(timezone.utc)
            health.consecutive_failures = 0
        else:
            # Count consecutive failures
            if self._health_history:
                last_health = self._health_history[-1]
                health.consecutive_failures = last_health.consecutive_failures + 1
                health.last_success = last_health.last_success

        self._health_history.append(health)
        if len(self._health_history) > 100:
            self._health_history.pop(0)

        # Calculate availability
        availability = self._calculate_availability()

        # Collect resource metrics
        resources = self.collect_resource_metrics()

        # Build infrastructure info
        infrastructure = InfrastructureInfo(
            instance_id=kwargs.get('instance_id', platform.node()),
            instance_type=kwargs.get('instance_type', ''),
            availability_zone=kwargs.get('availability_zone', ''),
            cluster_name=kwargs.get('cluster_name', ''),
            namespace=kwargs.get('namespace', ''),
            pod_name=kwargs.get('pod_name', ''),
            container_id=kwargs.get('container_id', ''),
            node_name=kwargs.get('node_name', ''),
        )

        metric = DevOpsMetric(
            event_type=EventType.HEALTH_CHECK,
            environment=kwargs.get('environment', 'production'),
            region=kwargs.get('region', ''),
            health=health,
            availability=availability,
            infrastructure=infrastructure,
            resources=resources,
        )

        with self._buffer_lock:
            self._metrics_buffer.append(metric)

        return metric

    def record_deployment(
        self,
        deployment_id: str,
        version: str,
        status: DeploymentStatus,
        **kwargs
    ) -> DevOpsMetric:
        """
        Record a deployment event.

        Args:
            deployment_id: Unique deployment identifier
            version: Version being deployed
            status: Deployment status
            **kwargs: Additional fields

        Returns:
            The recorded metric
        """
        now = datetime.now(timezone.utc)

        # Get or create deployment info
        if deployment_id in self._current_deployments:
            deployment = self._current_deployments[deployment_id]
            deployment.status = status
            if status == DeploymentStatus.COMPLETED:
                deployment.completed_at = now
                deployment.duration_seconds = (now - deployment.started_at).total_seconds()
        else:
            deployment = DeploymentInfo(
                id=deployment_id,
                version=version,
                previous_version=kwargs.get('previous_version'),
                model=kwargs.get('model'),
                model_version=kwargs.get('model_version'),
                status=status,
                strategy=kwargs.get('strategy', DeploymentStrategy.ROLLING),
                started_at=now,
                triggered_by=kwargs.get('triggered_by', ''),
                commit_sha=kwargs.get('commit_sha'),
                rollback=kwargs.get('rollback', False),
                rollback_reason=kwargs.get('rollback_reason'),
            )
            self._current_deployments[deployment_id] = deployment

        # Build canary info if applicable
        canary = None
        if kwargs.get('canary_enabled'):
            canary = CanaryInfo(
                enabled=True,
                traffic_percentage=kwargs.get('canary_traffic', 0.0),
                success_rate=kwargs.get('canary_success_rate', 0.0),
                latency_p50=kwargs.get('canary_latency_p50', 0.0),
                latency_p95=kwargs.get('canary_latency_p95', 0.0),
                error_rate=kwargs.get('canary_error_rate', 0.0),
                promoted=kwargs.get('canary_promoted', False),
                promotion_criteria_met=kwargs.get('canary_criteria_met', False),
            )

        metric = DevOpsMetric(
            event_type=EventType.DEPLOYMENT,
            environment=kwargs.get('environment', 'production'),
            region=kwargs.get('region', ''),
            deployment=deployment,
            canary=canary,
        )

        with self._buffer_lock:
            self._metrics_buffer.append(metric)

        return metric

    def record_scaling_event(
        self,
        event_type: ScalingEventType,
        current_replicas: int,
        desired_replicas: int,
        trigger: ScalingTrigger,
        metric_value: float,
        metric_threshold: float,
        **kwargs
    ) -> DevOpsMetric:
        """
        Record a scaling event.

        Args:
            event_type: Type of scaling event
            current_replicas: Current number of replicas
            desired_replicas: Desired number of replicas
            trigger: What triggered the scaling
            metric_value: Current metric value
            metric_threshold: Threshold that triggered scaling
            **kwargs: Additional fields

        Returns:
            The recorded metric
        """
        scaling = ScalingInfo(
            event_type=event_type,
            current_replicas=current_replicas,
            desired_replicas=desired_replicas,
            min_replicas=kwargs.get('min_replicas', self.devops_config.scaling.min_replicas),
            max_replicas=kwargs.get('max_replicas', self.devops_config.scaling.max_replicas),
            trigger=trigger,
            metric_value=metric_value,
            metric_threshold=metric_threshold,
            cooldown_remaining=kwargs.get('cooldown_remaining', 0),
        )

        metric = DevOpsMetric(
            event_type=EventType.SCALING,
            environment=kwargs.get('environment', 'production'),
            region=kwargs.get('region', ''),
            scaling=scaling,
        )

        with self._buffer_lock:
            self._metrics_buffer.append(metric)

        return metric

    def record_circuit_breaker_event(
        self,
        name: str,
        state: CircuitBreakerState,
        failure_count: int = 0,
        success_count: int = 0,
        **kwargs
    ) -> DevOpsMetric:
        """
        Record a circuit breaker event.

        Args:
            name: Circuit breaker name
            state: Current state
            failure_count: Number of failures
            success_count: Number of successes
            **kwargs: Additional fields

        Returns:
            The recorded metric
        """
        circuit_breaker = CircuitBreakerInfo(
            name=name,
            state=state,
            failure_count=failure_count,
            success_count=success_count,
            reset_timeout_seconds=kwargs.get('reset_timeout_seconds', 60),
        )

        if state == CircuitBreakerState.OPEN:
            circuit_breaker.last_failure = datetime.now(timezone.utc)

        self._circuit_breakers[name] = circuit_breaker

        metric = DevOpsMetric(
            event_type=EventType.CIRCUIT_BREAKER,
            environment=kwargs.get('environment', 'production'),
            circuit_breaker=circuit_breaker,
        )

        with self._buffer_lock:
            self._metrics_buffer.append(metric)

        return metric

    def record_incident(
        self,
        incident_id: str,
        severity: IncidentSeverity,
        status: IncidentStatus,
        **kwargs
    ) -> DevOpsMetric:
        """
        Record an incident.

        Args:
            incident_id: Unique incident identifier
            severity: Incident severity
            status: Incident status
            **kwargs: Additional fields

        Returns:
            The recorded metric
        """
        now = datetime.now(timezone.utc)

        if incident_id in self._active_incidents:
            incident = self._active_incidents[incident_id]
            incident.status = status
            if status == IncidentStatus.RESOLVED:
                incident.resolved_at = now
                incident.duration_seconds = int((now - incident.started_at).total_seconds())
                del self._active_incidents[incident_id]
        else:
            incident = IncidentInfo(
                id=incident_id,
                severity=severity,
                status=status,
                started_at=now,
                root_cause=kwargs.get('root_cause', ''),
                affected_services=kwargs.get('affected_services', []),
                impact_users=kwargs.get('impact_users', 0),
            )
            self._active_incidents[incident_id] = incident
            self._incident_count += 1

        metric = DevOpsMetric(
            event_type=EventType.INCIDENT,
            environment=kwargs.get('environment', 'production'),
            incident=incident,
        )

        with self._buffer_lock:
            self._metrics_buffer.append(metric)

        return metric

    def _calculate_availability(self) -> AvailabilityInfo:
        """Calculate current availability metrics."""
        now = datetime.now(timezone.utc)
        total_time = (now - self._uptime_start).total_seconds()

        uptime_seconds = total_time - self._total_downtime.total_seconds()
        uptime_percentage = (uptime_seconds / total_time) * 100 if total_time > 0 else 100.0

        sla_target = self.devops_config.scaling.target_latency_ms  # Simplified

        return AvailabilityInfo(
            uptime_percentage=uptime_percentage,
            downtime_seconds=int(self._total_downtime.total_seconds()),
            sla_target=99.9,
            sla_met=uptime_percentage >= 99.9,
            incident_count=self._incident_count,
        )

    def get_buffered_metrics(self, clear: bool = True) -> List[DevOpsMetric]:
        """Get buffered metrics."""
        with self._buffer_lock:
            metrics = self._metrics_buffer.copy()
            if clear:
                self._metrics_buffer.clear()
        return metrics

    def get_system_status(self) -> Dict[str, Any]:
        """Get current system status summary."""
        resources = self.collect_resource_metrics()

        return {
            "health": self._health_history[-1].status.value if self._health_history else "unknown",
            "availability": self._calculate_availability().__dict__,
            "active_deployments": len(self._current_deployments),
            "active_incidents": len(self._active_incidents),
            "circuit_breakers": {
                name: cb.state.value for name, cb in self._circuit_breakers.items()
            },
            "resources": {
                "cpu_percent": resources.cpu.usage_percent,
                "memory_percent": resources.memory.usage_percent,
                "disk_percent": resources.disk.usage_percent,
            },
        }
