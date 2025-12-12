"""
Configuration Manager for ELK Upgrade Audit Tool
=================================================
Handles loading, validation, and management of configuration settings.
"""

import os
import yaml
import logging
from pathlib import Path
from typing import Dict, Any, Optional
from dataclasses import dataclass, field


@dataclass
class ElasticsearchConfig:
    """Elasticsearch connection configuration."""
    hosts: list = field(default_factory=lambda: ["https://localhost:9200"])
    username: str = "elastic"
    password: str = ""
    verify_certs: bool = True
    ca_certs: str = ""
    timeout: int = 120
    max_retries: int = 3


@dataclass
class ClusterConfig:
    """Cluster information configuration."""
    name: str = "elk-cluster"
    environment: str = "production"


@dataclass
class UpgradeConfig:
    """Upgrade settings configuration."""
    target_version: str = "9.1.6"
    current_version: str = ""
    strategy: str = "rolling"


@dataclass
class AuditConfig:
    """Audit settings configuration."""
    reports_dir: str = "./reports"
    format: str = "html"
    checks: Dict[str, bool] = field(default_factory=lambda: {
        "cluster_health": True,
        "node_info": True,
        "index_health": True,
        "shard_allocation": True,
        "deprecation_warnings": True,
        "plugin_compatibility": True,
        "mapping_analysis": True,
        "snapshot_status": True,
        "disk_usage": True,
        "memory_usage": True
    })


@dataclass
class SnapshotConfig:
    """Snapshot/Backup configuration."""
    repository: str = "elk-backup"
    type: str = "fs"
    location: str = "/mnt/elasticsearch-backups"
    name_pattern: str = "pre-upgrade-{date}"


class ConfigManager:
    """
    Manages configuration loading and validation for the ELK Upgrade Audit Tool.
    """

    DEFAULT_CONFIG_PATH = Path(__file__).parent.parent / "config" / "settings.yaml"

    def __init__(self, config_path: Optional[str] = None):
        """
        Initialize the configuration manager.

        Args:
            config_path: Path to the configuration file. Uses default if not provided.
        """
        self.config_path = Path(config_path) if config_path else self.DEFAULT_CONFIG_PATH
        self.raw_config: Dict[str, Any] = {}
        self.elasticsearch = ElasticsearchConfig()
        self.cluster = ClusterConfig()
        self.upgrade = UpgradeConfig()
        self.audit = AuditConfig()
        self.snapshot = SnapshotConfig()
        self.logger = logging.getLogger(__name__)

    def load(self) -> bool:
        """
        Load configuration from the YAML file.

        Returns:
            True if configuration was loaded successfully, False otherwise.
        """
        try:
            if not self.config_path.exists():
                self.logger.warning(f"Configuration file not found: {self.config_path}")
                self.logger.info("Using default configuration")
                return True

            with open(self.config_path, 'r', encoding='utf-8') as f:
                self.raw_config = yaml.safe_load(f) or {}

            self._parse_elasticsearch_config()
            self._parse_cluster_config()
            self._parse_upgrade_config()
            self._parse_audit_config()
            self._parse_snapshot_config()

            self.logger.info(f"Configuration loaded from {self.config_path}")
            return True

        except yaml.YAMLError as e:
            self.logger.error(f"Error parsing configuration file: {e}")
            return False
        except Exception as e:
            self.logger.error(f"Error loading configuration: {e}")
            return False

    def _parse_elasticsearch_config(self):
        """Parse Elasticsearch configuration section."""
        es_config = self.raw_config.get('elasticsearch', {})
        self.elasticsearch = ElasticsearchConfig(
            hosts=es_config.get('hosts', self.elasticsearch.hosts),
            username=es_config.get('username', self.elasticsearch.username),
            password=self._get_password(es_config),
            verify_certs=es_config.get('verify_certs', self.elasticsearch.verify_certs),
            ca_certs=es_config.get('ca_certs', self.elasticsearch.ca_certs),
            timeout=es_config.get('timeout', self.elasticsearch.timeout),
            max_retries=es_config.get('max_retries', self.elasticsearch.max_retries)
        )

    def _get_password(self, es_config: Dict) -> str:
        """Get password from config or environment variable."""
        password = es_config.get('password', '')
        if not password:
            password = os.environ.get('ES_PASSWORD', '')
        return password

    def _parse_cluster_config(self):
        """Parse cluster configuration section."""
        cluster_config = self.raw_config.get('cluster', {})
        self.cluster = ClusterConfig(
            name=cluster_config.get('name', self.cluster.name),
            environment=cluster_config.get('environment', self.cluster.environment)
        )

    def _parse_upgrade_config(self):
        """Parse upgrade configuration section."""
        upgrade_config = self.raw_config.get('upgrade', {})
        self.upgrade = UpgradeConfig(
            target_version=upgrade_config.get('target_version', self.upgrade.target_version),
            current_version=upgrade_config.get('current_version', self.upgrade.current_version),
            strategy=upgrade_config.get('strategy', self.upgrade.strategy)
        )

    def _parse_audit_config(self):
        """Parse audit configuration section."""
        audit_config = self.raw_config.get('audit', {})
        self.audit = AuditConfig(
            reports_dir=audit_config.get('reports_dir', self.audit.reports_dir),
            format=audit_config.get('format', self.audit.format),
            checks=audit_config.get('checks', self.audit.checks)
        )

    def _parse_snapshot_config(self):
        """Parse snapshot configuration section."""
        snapshot_config = self.raw_config.get('snapshot', {})
        self.snapshot = SnapshotConfig(
            repository=snapshot_config.get('repository', self.snapshot.repository),
            type=snapshot_config.get('type', self.snapshot.type),
            location=snapshot_config.get('location', self.snapshot.location),
            name_pattern=snapshot_config.get('name_pattern', self.snapshot.name_pattern)
        )

    def validate(self) -> tuple[bool, list[str]]:
        """
        Validate the current configuration.

        Returns:
            Tuple of (is_valid, list of error messages)
        """
        errors = []

        # Validate Elasticsearch hosts
        if not self.elasticsearch.hosts:
            errors.append("At least one Elasticsearch host must be configured")

        # Validate upgrade target version
        if not self.upgrade.target_version:
            errors.append("Target upgrade version must be specified")

        # Validate upgrade strategy
        valid_strategies = ['rolling', 'full-cluster-restart']
        if self.upgrade.strategy not in valid_strategies:
            errors.append(f"Invalid upgrade strategy. Must be one of: {valid_strategies}")

        # Validate environment
        valid_environments = ['production', 'staging', 'development']
        if self.cluster.environment not in valid_environments:
            errors.append(f"Invalid environment. Must be one of: {valid_environments}")

        # Validate report format
        valid_formats = ['html', 'json', 'markdown']
        if self.audit.format not in valid_formats:
            errors.append(f"Invalid report format. Must be one of: {valid_formats}")

        return (len(errors) == 0, errors)

    def to_dict(self) -> Dict[str, Any]:
        """
        Convert configuration to dictionary.

        Returns:
            Dictionary representation of the configuration.
        """
        return {
            'elasticsearch': {
                'hosts': self.elasticsearch.hosts,
                'username': self.elasticsearch.username,
                'verify_certs': self.elasticsearch.verify_certs,
                'timeout': self.elasticsearch.timeout,
                'max_retries': self.elasticsearch.max_retries
            },
            'cluster': {
                'name': self.cluster.name,
                'environment': self.cluster.environment
            },
            'upgrade': {
                'target_version': self.upgrade.target_version,
                'current_version': self.upgrade.current_version,
                'strategy': self.upgrade.strategy
            },
            'audit': {
                'reports_dir': self.audit.reports_dir,
                'format': self.audit.format,
                'checks': self.audit.checks
            },
            'snapshot': {
                'repository': self.snapshot.repository,
                'type': self.snapshot.type,
                'location': self.snapshot.location,
                'name_pattern': self.snapshot.name_pattern
            }
        }

    def save(self, path: Optional[str] = None) -> bool:
        """
        Save current configuration to a YAML file.

        Args:
            path: Path to save the configuration. Uses current config_path if not provided.

        Returns:
            True if saved successfully, False otherwise.
        """
        save_path = Path(path) if path else self.config_path

        try:
            save_path.parent.mkdir(parents=True, exist_ok=True)
            with open(save_path, 'w', encoding='utf-8') as f:
                yaml.dump(self.to_dict(), f, default_flow_style=False, sort_keys=False)
            self.logger.info(f"Configuration saved to {save_path}")
            return True
        except Exception as e:
            self.logger.error(f"Error saving configuration: {e}")
            return False


def setup_logging(level: str = "INFO", log_file: Optional[str] = None):
    """
    Setup logging configuration.

    Args:
        level: Logging level (DEBUG, INFO, WARNING, ERROR)
        log_file: Optional path to log file
    """
    log_format = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'

    handlers = [logging.StreamHandler()]

    if log_file:
        log_path = Path(log_file)
        log_path.parent.mkdir(parents=True, exist_ok=True)
        handlers.append(logging.FileHandler(log_file))

    logging.basicConfig(
        level=getattr(logging, level.upper()),
        format=log_format,
        handlers=handlers
    )
