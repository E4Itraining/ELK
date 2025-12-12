"""
Configuration Management Module
===============================

Handles loading and validating configuration from YAML files
with support for environment variable substitution.
"""

import os
import re
import yaml
import logging
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any
from pathlib import Path

logger = logging.getLogger(__name__)


@dataclass
class ElasticsearchConfig:
    """Elasticsearch connection configuration."""
    hosts: List[str] = field(default_factory=lambda: ["https://localhost:9200"])
    username: str = "elastic"
    password: str = ""
    ca_certs: Optional[str] = None
    verify_certs: bool = True
    ssl_show_warn: bool = True
    timeout: int = 120
    max_retries: int = 3


@dataclass
class KibanaConfig:
    """Kibana connection configuration."""
    host: str = "http://localhost:5601"
    username: str = "elastic"
    password: str = ""


@dataclass
class ProviderCosts:
    """Cost per 1K tokens for input and output."""
    input: float = 0.0
    output: float = 0.0


@dataclass
class AIProviderConfig:
    """AI provider configuration."""
    enabled: bool = False
    api_key: str = ""
    models: List[str] = field(default_factory=list)
    cost_per_1k_tokens: Dict[str, ProviderCosts] = field(default_factory=dict)
    endpoint: Optional[str] = None


@dataclass
class LatencyThresholds:
    """Latency threshold configuration."""
    p50_warning: int = 500
    p50_critical: int = 1000
    p95_warning: int = 2000
    p95_critical: int = 5000
    p99_warning: int = 5000
    p99_critical: int = 10000


@dataclass
class ErrorRateThresholds:
    """Error rate threshold configuration."""
    warning: float = 1.0
    critical: float = 5.0


@dataclass
class TechnicalConfig:
    """Technical monitoring configuration."""
    enabled: bool = True
    index_prefix: str = "ai-technical-metrics"
    latency: LatencyThresholds = field(default_factory=LatencyThresholds)
    error_rate: ErrorRateThresholds = field(default_factory=ErrorRateThresholds)
    availability_target: float = 99.9


@dataclass
class QualityConfig:
    """Quality evaluation configuration."""
    enabled: bool = True
    evaluation_sample_rate: float = 0.1
    min_quality_score: float = 0.7


@dataclass
class HallucinationConfig:
    """Hallucination detection configuration."""
    enabled: bool = True
    detection_model: str = "internal"
    confidence_threshold: float = 0.8
    alert_on_detection: bool = True


@dataclass
class BiasConfig:
    """Bias detection configuration."""
    enabled: bool = True
    categories: List[str] = field(default_factory=lambda: [
        "gender", "race", "age", "religion", "political"
    ])
    threshold: float = 0.3


@dataclass
class ToxicityConfig:
    """Toxicity detection configuration."""
    enabled: bool = True
    threshold: float = 0.5
    categories: List[str] = field(default_factory=lambda: [
        "hate_speech", "harassment", "violence", "sexual_content", "self_harm"
    ])


@dataclass
class CognitiveConfig:
    """Cognitive monitoring configuration."""
    enabled: bool = True
    index_prefix: str = "ai-cognitive-metrics"
    quality: QualityConfig = field(default_factory=QualityConfig)
    hallucination: HallucinationConfig = field(default_factory=HallucinationConfig)
    bias: BiasConfig = field(default_factory=BiasConfig)
    toxicity: ToxicityConfig = field(default_factory=ToxicityConfig)


@dataclass
class BudgetConfig:
    """Budget management configuration."""
    daily_limit: float = 1000.0
    weekly_limit: float = 5000.0
    monthly_limit: float = 15000.0
    alert_at_percentage: List[int] = field(default_factory=lambda: [50, 75, 90, 100])


@dataclass
class CostAllocationConfig:
    """Cost allocation configuration."""
    track_by: List[str] = field(default_factory=lambda: [
        "team", "project", "environment", "user", "model"
    ])


@dataclass
class ROIConfig:
    """ROI tracking configuration."""
    track_business_value: bool = True
    value_per_successful_interaction: float = 5.0


@dataclass
class FinOpsConfig:
    """FinOps monitoring configuration."""
    enabled: bool = True
    index_prefix: str = "ai-finops-metrics"
    budget: BudgetConfig = field(default_factory=BudgetConfig)
    cost_allocation: CostAllocationConfig = field(default_factory=CostAllocationConfig)
    roi: ROIConfig = field(default_factory=ROIConfig)


@dataclass
class ScalingConfig:
    """Scaling configuration."""
    auto_scale_enabled: bool = True
    min_replicas: int = 2
    max_replicas: int = 20
    target_latency_ms: int = 500
    scale_up_threshold: float = 0.7
    scale_down_threshold: float = 0.3


@dataclass
class HealthCheckConfig:
    """Health check configuration."""
    liveness_interval: int = 30
    readiness_interval: int = 10
    startup_timeout: int = 120


@dataclass
class DevOpsConfig:
    """DevOps monitoring configuration."""
    enabled: bool = True
    index_prefix: str = "ai-devops-metrics"
    scaling: ScalingConfig = field(default_factory=ScalingConfig)
    health: HealthCheckConfig = field(default_factory=HealthCheckConfig)
    track_gpu_usage: bool = True


@dataclass
class GDPRConfig:
    """GDPR compliance configuration."""
    enabled: bool = True
    data_retention_days: int = 90
    anonymization_enabled: bool = True
    pii_detection: bool = True
    consent_tracking: bool = True
    right_to_forget: bool = True


@dataclass
class AuditConfig:
    """Audit logging configuration."""
    enabled: bool = True
    log_all_requests: bool = True
    log_all_responses: bool = True
    include_metadata: bool = True
    retention_days: int = 365


@dataclass
class DataClassificationConfig:
    """Data classification configuration."""
    enabled: bool = True
    levels: List[str] = field(default_factory=lambda: [
        "public", "internal", "confidential", "restricted"
    ])


@dataclass
class ModelGovernanceConfig:
    """Model governance configuration."""
    model_registry: bool = True
    version_tracking: bool = True
    approval_workflow: bool = True
    risk_assessment: bool = True


@dataclass
class ComplianceConfig:
    """Compliance monitoring configuration."""
    enabled: bool = True
    index_prefix: str = "ai-compliance-metrics"
    gdpr: GDPRConfig = field(default_factory=GDPRConfig)
    audit: AuditConfig = field(default_factory=AuditConfig)
    classification: DataClassificationConfig = field(default_factory=DataClassificationConfig)
    governance: ModelGovernanceConfig = field(default_factory=ModelGovernanceConfig)


@dataclass
class SlackChannelConfig:
    """Slack channel configuration."""
    enabled: bool = True
    webhook_url: str = ""
    channels: Dict[str, str] = field(default_factory=dict)


@dataclass
class EmailConfig:
    """Email configuration."""
    enabled: bool = True
    smtp_host: str = ""
    smtp_port: int = 587
    from_address: str = ""
    recipients: Dict[str, List[str]] = field(default_factory=dict)


@dataclass
class AlertRule:
    """Alert rule configuration."""
    name: str = ""
    condition: str = ""
    severity: str = "warning"
    cooldown_minutes: int = 15


@dataclass
class AlertingConfig:
    """Alerting configuration."""
    enabled: bool = True
    slack: SlackChannelConfig = field(default_factory=SlackChannelConfig)
    email: EmailConfig = field(default_factory=EmailConfig)
    rules: List[AlertRule] = field(default_factory=list)


@dataclass
class LoggingConfig:
    """Logging configuration."""
    level: str = "INFO"
    format: str = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    file: str = "./logs/ai-monitoring.log"
    max_size_mb: int = 100
    backup_count: int = 10


@dataclass
class CollectionConfig:
    """Data collection configuration."""
    batch_size: int = 100
    flush_interval_seconds: int = 10
    retry_on_failure: bool = True
    max_retries: int = 3
    dead_letter_queue: bool = True


@dataclass
class Config:
    """Main configuration container."""
    elasticsearch: ElasticsearchConfig = field(default_factory=ElasticsearchConfig)
    kibana: KibanaConfig = field(default_factory=KibanaConfig)
    ai_providers: Dict[str, AIProviderConfig] = field(default_factory=dict)
    technical: TechnicalConfig = field(default_factory=TechnicalConfig)
    cognitive: CognitiveConfig = field(default_factory=CognitiveConfig)
    finops: FinOpsConfig = field(default_factory=FinOpsConfig)
    devops: DevOpsConfig = field(default_factory=DevOpsConfig)
    compliance: ComplianceConfig = field(default_factory=ComplianceConfig)
    alerting: AlertingConfig = field(default_factory=AlertingConfig)
    logging: LoggingConfig = field(default_factory=LoggingConfig)
    collection: CollectionConfig = field(default_factory=CollectionConfig)


def substitute_env_vars(value: Any) -> Any:
    """Substitute environment variables in string values."""
    if isinstance(value, str):
        # Match ${VAR_NAME} pattern
        pattern = re.compile(r'\$\{([^}]+)\}')

        def replace(match):
            var_name = match.group(1)
            return os.environ.get(var_name, "")

        return pattern.sub(replace, value)
    elif isinstance(value, dict):
        return {k: substitute_env_vars(v) for k, v in value.items()}
    elif isinstance(value, list):
        return [substitute_env_vars(item) for item in value]
    return value


def load_config(config_path: str = None) -> Config:
    """
    Load configuration from YAML file.

    Args:
        config_path: Path to configuration file. If None, looks for
                    config/settings.yaml or config/settings.local.yaml

    Returns:
        Config object with loaded configuration
    """
    if config_path is None:
        # Look for local config first, then default
        base_path = Path(__file__).parent.parent
        local_path = base_path / "config" / "settings.local.yaml"
        default_path = base_path / "config" / "settings.yaml"

        if local_path.exists():
            config_path = str(local_path)
        elif default_path.exists():
            config_path = str(default_path)
        else:
            logger.warning("No configuration file found, using defaults")
            return Config()

    try:
        with open(config_path, 'r') as f:
            raw_config = yaml.safe_load(f)

        # Substitute environment variables
        config_data = substitute_env_vars(raw_config)

        # Build configuration object
        config = Config()

        # Parse Elasticsearch config
        if 'elasticsearch' in config_data:
            es_data = config_data['elasticsearch']
            config.elasticsearch = ElasticsearchConfig(
                hosts=es_data.get('hosts', config.elasticsearch.hosts),
                username=es_data.get('username', config.elasticsearch.username),
                password=es_data.get('password', config.elasticsearch.password),
                ca_certs=es_data.get('ca_certs'),
                verify_certs=es_data.get('verify_certs', config.elasticsearch.verify_certs),
                ssl_show_warn=es_data.get('ssl_show_warn', config.elasticsearch.ssl_show_warn),
                timeout=es_data.get('timeout', config.elasticsearch.timeout),
                max_retries=es_data.get('max_retries', config.elasticsearch.max_retries),
            )

        # Parse Kibana config
        if 'kibana' in config_data:
            kb_data = config_data['kibana']
            config.kibana = KibanaConfig(
                host=kb_data.get('host', config.kibana.host),
                username=kb_data.get('username', config.kibana.username),
                password=kb_data.get('password', config.kibana.password),
            )

        # Parse AI providers
        if 'ai_providers' in config_data:
            for provider_name, provider_data in config_data['ai_providers'].items():
                costs = {}
                if 'cost_per_1k_tokens' in provider_data:
                    for model, cost_data in provider_data['cost_per_1k_tokens'].items():
                        costs[model] = ProviderCosts(
                            input=cost_data.get('input', 0.0),
                            output=cost_data.get('output', 0.0),
                        )

                config.ai_providers[provider_name] = AIProviderConfig(
                    enabled=provider_data.get('enabled', False),
                    api_key=provider_data.get('api_key', ''),
                    models=provider_data.get('models', []),
                    cost_per_1k_tokens=costs,
                    endpoint=provider_data.get('endpoint'),
                )

        # Parse technical config
        if 'technical' in config_data:
            tech_data = config_data['technical']
            latency_data = tech_data.get('latency', {})
            error_data = tech_data.get('error_rate', {})

            config.technical = TechnicalConfig(
                enabled=tech_data.get('enabled', True),
                index_prefix=tech_data.get('index_prefix', 'ai-technical-metrics'),
                latency=LatencyThresholds(
                    p50_warning=latency_data.get('p50_warning', 500),
                    p50_critical=latency_data.get('p50_critical', 1000),
                    p95_warning=latency_data.get('p95_warning', 2000),
                    p95_critical=latency_data.get('p95_critical', 5000),
                    p99_warning=latency_data.get('p99_warning', 5000),
                    p99_critical=latency_data.get('p99_critical', 10000),
                ),
                error_rate=ErrorRateThresholds(
                    warning=error_data.get('warning', 1.0),
                    critical=error_data.get('critical', 5.0),
                ),
                availability_target=tech_data.get('availability', {}).get(
                    'target_percentage', 99.9
                ),
            )

        # Parse cognitive config
        if 'cognitive' in config_data:
            cog_data = config_data['cognitive']
            config.cognitive = CognitiveConfig(
                enabled=cog_data.get('enabled', True),
                index_prefix=cog_data.get('index_prefix', 'ai-cognitive-metrics'),
                quality=QualityConfig(**cog_data.get('quality', {})),
                hallucination=HallucinationConfig(**cog_data.get('hallucination', {})),
                bias=BiasConfig(**cog_data.get('bias', {})),
                toxicity=ToxicityConfig(**cog_data.get('toxicity', {})),
            )

        # Parse finops config
        if 'finops' in config_data:
            fin_data = config_data['finops']
            config.finops = FinOpsConfig(
                enabled=fin_data.get('enabled', True),
                index_prefix=fin_data.get('index_prefix', 'ai-finops-metrics'),
                budget=BudgetConfig(**fin_data.get('budget', {})),
                cost_allocation=CostAllocationConfig(**fin_data.get('cost_allocation', {})),
                roi=ROIConfig(**fin_data.get('roi', {})),
            )

        # Parse devops config
        if 'devops' in config_data:
            dev_data = config_data['devops']
            config.devops = DevOpsConfig(
                enabled=dev_data.get('enabled', True),
                index_prefix=dev_data.get('index_prefix', 'ai-devops-metrics'),
                scaling=ScalingConfig(**dev_data.get('scaling', {})),
                health=HealthCheckConfig(**dev_data.get('health', {})),
                track_gpu_usage=dev_data.get('infrastructure', {}).get('track_gpu_usage', True),
            )

        # Parse compliance config
        if 'compliance' in config_data:
            comp_data = config_data['compliance']
            config.compliance = ComplianceConfig(
                enabled=comp_data.get('enabled', True),
                index_prefix=comp_data.get('index_prefix', 'ai-compliance-metrics'),
                gdpr=GDPRConfig(**comp_data.get('gdpr', {})),
                audit=AuditConfig(**comp_data.get('audit', {})),
                classification=DataClassificationConfig(**comp_data.get('classification', {})),
                governance=ModelGovernanceConfig(**comp_data.get('governance', {})),
            )

        # Parse alerting config
        if 'alerting' in config_data:
            alert_data = config_data['alerting']
            rules = []
            for rule_data in alert_data.get('rules', []):
                rules.append(AlertRule(**rule_data))

            config.alerting = AlertingConfig(
                enabled=alert_data.get('enabled', True),
                slack=SlackChannelConfig(**alert_data.get('channels', {}).get('slack', {})),
                email=EmailConfig(**alert_data.get('channels', {}).get('email', {})),
                rules=rules,
            )

        # Parse logging config
        if 'logging' in config_data:
            log_data = config_data['logging']
            config.logging = LoggingConfig(
                level=log_data.get('level', 'INFO'),
                format=log_data.get('format', config.logging.format),
                file=log_data.get('file', config.logging.file),
                max_size_mb=log_data.get('max_size_mb', 100),
                backup_count=log_data.get('backup_count', 10),
            )

        # Parse collection config
        if 'collection' in config_data:
            coll_data = config_data['collection']
            config.collection = CollectionConfig(
                batch_size=coll_data.get('batch_size', 100),
                flush_interval_seconds=coll_data.get('flush_interval_seconds', 10),
                retry_on_failure=coll_data.get('retry_on_failure', True),
                max_retries=coll_data.get('max_retries', 3),
                dead_letter_queue=coll_data.get('dead_letter_queue', True),
            )

        logger.info(f"Configuration loaded from {config_path}")
        return config

    except FileNotFoundError:
        logger.error(f"Configuration file not found: {config_path}")
        raise
    except yaml.YAMLError as e:
        logger.error(f"Error parsing YAML configuration: {e}")
        raise
    except Exception as e:
        logger.error(f"Error loading configuration: {e}")
        raise
