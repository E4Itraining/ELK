"""
AI Monitoring & Observability Platform
======================================

Comprehensive monitoring for AI systems across multiple dimensions:
- Technical: Latency, throughput, errors, availability
- Cognitive: Quality, hallucination, bias, toxicity
- FinOps: Costs, budget, ROI, optimization
- DevOps: Deployment, scaling, health, resources
- Compliance: GDPR, audit, data classification, governance
"""

from .config import Config, load_config
from .elasticsearch_client import AIMonitoringClient
from .technical_monitor import TechnicalMonitor
from .cognitive_monitor import CognitiveMonitor
from .finops_monitor import FinOpsMonitor
from .devops_monitor import DevOpsMonitor
from .compliance_monitor import ComplianceMonitor
from .metrics_collector import MetricsCollector
from .alerting import AlertManager

__version__ = "1.0.0"
__author__ = "AI Monitoring Team"

__all__ = [
    "Config",
    "load_config",
    "AIMonitoringClient",
    "TechnicalMonitor",
    "CognitiveMonitor",
    "FinOpsMonitor",
    "DevOpsMonitor",
    "ComplianceMonitor",
    "MetricsCollector",
    "AlertManager",
]
