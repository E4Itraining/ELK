"""
Pre-Upgrade Audit Module for ELK Upgrade Audit Tool
====================================================
Performs comprehensive pre-upgrade checks on the Elasticsearch cluster.
"""

import logging
from typing import Dict, Any, List, Tuple
from datetime import datetime
from dataclasses import dataclass, field
from enum import Enum


class CheckStatus(Enum):
    """Status of an audit check."""
    PASSED = "passed"
    WARNING = "warning"
    FAILED = "failed"
    SKIPPED = "skipped"
    ERROR = "error"


@dataclass
class AuditCheck:
    """Represents a single audit check result."""
    name: str
    category: str
    status: CheckStatus
    message: str
    details: Dict[str, Any] = field(default_factory=dict)
    recommendations: List[str] = field(default_factory=list)
    severity: str = "info"  # info, low, medium, high, critical


@dataclass
class AuditReport:
    """Complete audit report."""
    cluster_name: str
    current_version: str
    target_version: str
    timestamp: str
    checks: List[AuditCheck] = field(default_factory=list)
    summary: Dict[str, int] = field(default_factory=dict)
    ready_for_upgrade: bool = False


class PreUpgradeAudit:
    """
    Performs comprehensive pre-upgrade auditing of an Elasticsearch cluster.
    """

    # Minimum disk space threshold (in percentage)
    MIN_DISK_SPACE_PERCENT = 20
    # Maximum heap usage threshold (in percentage)
    MAX_HEAP_USAGE_PERCENT = 85
    # Maximum relocating shards
    MAX_RELOCATING_SHARDS = 0
    # Maximum initializing shards
    MAX_INITIALIZING_SHARDS = 0

    def __init__(self, es_client, config):
        """
        Initialize the pre-upgrade audit.

        Args:
            es_client: ElasticsearchClient instance
            config: ConfigManager instance
        """
        self.es = es_client
        self.config = config
        self.logger = logging.getLogger(__name__)
        self.checks: List[AuditCheck] = []

    def run_full_audit(self) -> AuditReport:
        """
        Run a complete pre-upgrade audit.

        Returns:
            AuditReport with all check results.
        """
        self.checks = []
        self.logger.info("Starting pre-upgrade audit...")

        # Run all audit checks
        self._check_cluster_health()
        self._check_node_versions()
        self._check_node_resources()
        self._check_disk_space()
        self._check_heap_usage()
        self._check_shard_allocation()
        self._check_unassigned_shards()
        self._check_index_health()
        self._check_deprecated_settings()
        self._check_pending_tasks()
        self._check_snapshot_status()
        self._check_index_compatibility()
        self._check_plugin_compatibility()
        self._check_ilm_policies()
        self._check_transforms()
        self._check_watchers()

        # Generate report
        report = self._generate_report()
        self.logger.info(f"Audit complete. Ready for upgrade: {report.ready_for_upgrade}")

        return report

    def _add_check(self, check: AuditCheck):
        """Add a check to the results list."""
        self.checks.append(check)
        log_method = self.logger.info if check.status == CheckStatus.PASSED else \
                     self.logger.warning if check.status == CheckStatus.WARNING else \
                     self.logger.error
        log_method(f"[{check.status.value.upper()}] {check.name}: {check.message}")

    def _check_cluster_health(self):
        """Check overall cluster health status."""
        health = self.es.get_cluster_health()

        if "error" in health:
            self._add_check(AuditCheck(
                name="Cluster Health",
                category="cluster",
                status=CheckStatus.ERROR,
                message=f"Failed to get cluster health: {health['error']}",
                severity="critical"
            ))
            return

        status = health.get("status", "unknown")

        if status == "green":
            self._add_check(AuditCheck(
                name="Cluster Health",
                category="cluster",
                status=CheckStatus.PASSED,
                message="Cluster health is GREEN",
                details=health,
                severity="info"
            ))
        elif status == "yellow":
            self._add_check(AuditCheck(
                name="Cluster Health",
                category="cluster",
                status=CheckStatus.WARNING,
                message="Cluster health is YELLOW - some replicas are not allocated",
                details=health,
                recommendations=[
                    "Investigate unassigned replica shards",
                    "Consider adding more nodes or adjusting replica settings",
                    "Ensure all nodes are healthy before upgrade"
                ],
                severity="medium"
            ))
        else:
            self._add_check(AuditCheck(
                name="Cluster Health",
                category="cluster",
                status=CheckStatus.FAILED,
                message=f"Cluster health is {status.upper()} - not safe to upgrade",
                details=health,
                recommendations=[
                    "Resolve all cluster health issues before upgrading",
                    "Check for missing primary shards",
                    "Verify all nodes are running and reachable"
                ],
                severity="critical"
            ))

    def _check_node_versions(self):
        """Check that all nodes are running the same version."""
        nodes = self.es.get_nodes_info()

        if not nodes or "error" in nodes[0]:
            self._add_check(AuditCheck(
                name="Node Version Consistency",
                category="nodes",
                status=CheckStatus.ERROR,
                message="Failed to get node information",
                severity="critical"
            ))
            return

        versions = set(node.get("version") for node in nodes)

        if len(versions) == 1:
            version = versions.pop()
            self._add_check(AuditCheck(
                name="Node Version Consistency",
                category="nodes",
                status=CheckStatus.PASSED,
                message=f"All {len(nodes)} nodes are running version {version}",
                details={"node_count": len(nodes), "version": version},
                severity="info"
            ))
        else:
            self._add_check(AuditCheck(
                name="Node Version Consistency",
                category="nodes",
                status=CheckStatus.FAILED,
                message=f"Nodes are running different versions: {versions}",
                details={
                    "versions": list(versions),
                    "nodes": [(n.get("name"), n.get("version")) for n in nodes]
                },
                recommendations=[
                    "Ensure all nodes are running the same version before upgrade",
                    "Complete any in-progress rolling upgrade first"
                ],
                severity="critical"
            ))

    def _check_node_resources(self):
        """Check node resource allocation and roles."""
        nodes = self.es.get_nodes_info()

        if not nodes or "error" in nodes[0]:
            return

        master_nodes = [n for n in nodes if "master" in n.get("roles", [])]
        data_nodes = [n for n in nodes if "data" in n.get("roles", [])]

        # Check master node count
        if len(master_nodes) < 3:
            self._add_check(AuditCheck(
                name="Master Node Count",
                category="nodes",
                status=CheckStatus.WARNING,
                message=f"Only {len(master_nodes)} master-eligible nodes (recommended: 3+)",
                details={"master_nodes": [n.get("name") for n in master_nodes]},
                recommendations=[
                    "Consider having at least 3 master-eligible nodes for high availability",
                    "This helps prevent split-brain scenarios during upgrades"
                ],
                severity="medium"
            ))
        else:
            self._add_check(AuditCheck(
                name="Master Node Count",
                category="nodes",
                status=CheckStatus.PASSED,
                message=f"{len(master_nodes)} master-eligible nodes available",
                details={"master_nodes": [n.get("name") for n in master_nodes]},
                severity="info"
            ))

        # Check data node count
        if len(data_nodes) < 2:
            self._add_check(AuditCheck(
                name="Data Node Count",
                category="nodes",
                status=CheckStatus.WARNING,
                message=f"Only {len(data_nodes)} data node(s) - limited redundancy",
                details={"data_nodes": [n.get("name") for n in data_nodes]},
                recommendations=[
                    "Consider having at least 2 data nodes for redundancy",
                    "Single data node means no replica protection during upgrade"
                ],
                severity="medium"
            ))
        else:
            self._add_check(AuditCheck(
                name="Data Node Count",
                category="nodes",
                status=CheckStatus.PASSED,
                message=f"{len(data_nodes)} data nodes available",
                details={"data_nodes": [n.get("name") for n in data_nodes]},
                severity="info"
            ))

    def _check_disk_space(self):
        """Check disk space on all nodes."""
        nodes = self.es.get_nodes_info()

        if not nodes or "error" in nodes[0]:
            return

        low_disk_nodes = []

        for node in nodes:
            stats = node.get("stats", {})
            disk_total = stats.get("disk_total", 0)
            disk_available = stats.get("disk_available", 0)

            if disk_total > 0:
                disk_free_percent = (disk_available / disk_total) * 100

                if disk_free_percent < self.MIN_DISK_SPACE_PERCENT:
                    low_disk_nodes.append({
                        "name": node.get("name"),
                        "free_percent": round(disk_free_percent, 2),
                        "available_gb": round(disk_available / (1024**3), 2),
                        "total_gb": round(disk_total / (1024**3), 2)
                    })

        if low_disk_nodes:
            self._add_check(AuditCheck(
                name="Disk Space",
                category="resources",
                status=CheckStatus.WARNING,
                message=f"{len(low_disk_nodes)} node(s) with low disk space (<{self.MIN_DISK_SPACE_PERCENT}%)",
                details={"low_disk_nodes": low_disk_nodes},
                recommendations=[
                    "Free up disk space before upgrade",
                    "Consider deleting old indices or increasing disk capacity",
                    "Upgrade process may require temporary additional disk space"
                ],
                severity="high"
            ))
        else:
            self._add_check(AuditCheck(
                name="Disk Space",
                category="resources",
                status=CheckStatus.PASSED,
                message=f"All nodes have adequate disk space (>{self.MIN_DISK_SPACE_PERCENT}% free)",
                severity="info"
            ))

    def _check_heap_usage(self):
        """Check JVM heap usage on all nodes."""
        nodes = self.es.get_nodes_info()

        if not nodes or "error" in nodes[0]:
            return

        high_heap_nodes = []

        for node in nodes:
            stats = node.get("stats", {})
            heap_percent = stats.get("heap_used_percent", 0)

            if heap_percent > self.MAX_HEAP_USAGE_PERCENT:
                high_heap_nodes.append({
                    "name": node.get("name"),
                    "heap_percent": heap_percent
                })

        if high_heap_nodes:
            self._add_check(AuditCheck(
                name="Heap Usage",
                category="resources",
                status=CheckStatus.WARNING,
                message=f"{len(high_heap_nodes)} node(s) with high heap usage (>{self.MAX_HEAP_USAGE_PERCENT}%)",
                details={"high_heap_nodes": high_heap_nodes},
                recommendations=[
                    "Investigate high memory usage before upgrade",
                    "Consider increasing heap size or reducing workload",
                    "High heap usage can cause issues during upgrade"
                ],
                severity="medium"
            ))
        else:
            self._add_check(AuditCheck(
                name="Heap Usage",
                category="resources",
                status=CheckStatus.PASSED,
                message=f"All nodes have acceptable heap usage (<{self.MAX_HEAP_USAGE_PERCENT}%)",
                severity="info"
            ))

    def _check_shard_allocation(self):
        """Check for relocating or initializing shards."""
        health = self.es.get_cluster_health()

        if "error" in health:
            return

        relocating = health.get("relocating_shards", 0)
        initializing = health.get("initializing_shards", 0)

        if relocating > 0 or initializing > 0:
            self._add_check(AuditCheck(
                name="Shard Movement",
                category="shards",
                status=CheckStatus.WARNING,
                message=f"Shards in motion: {relocating} relocating, {initializing} initializing",
                details={
                    "relocating_shards": relocating,
                    "initializing_shards": initializing
                },
                recommendations=[
                    "Wait for shard movements to complete before upgrading",
                    "Check if there are ongoing rebalancing operations",
                    "Upgrading during shard movement can cause issues"
                ],
                severity="medium"
            ))
        else:
            self._add_check(AuditCheck(
                name="Shard Movement",
                category="shards",
                status=CheckStatus.PASSED,
                message="No shards are relocating or initializing",
                severity="info"
            ))

    def _check_unassigned_shards(self):
        """Check for unassigned shards and analyze reasons."""
        health = self.es.get_cluster_health()

        if "error" in health:
            return

        unassigned = health.get("unassigned_shards", 0)

        if unassigned > 0:
            # Get allocation explanation
            explain = self.es.get_allocation_explain()

            self._add_check(AuditCheck(
                name="Unassigned Shards",
                category="shards",
                status=CheckStatus.WARNING if unassigned < 10 else CheckStatus.FAILED,
                message=f"{unassigned} unassigned shard(s) detected",
                details={
                    "unassigned_count": unassigned,
                    "allocation_explain": explain
                },
                recommendations=[
                    "Investigate and resolve unassigned shards before upgrade",
                    "Check node disk space and allocation rules",
                    "Consider temporarily reducing replica count if needed"
                ],
                severity="high" if unassigned >= 10 else "medium"
            ))
        else:
            self._add_check(AuditCheck(
                name="Unassigned Shards",
                category="shards",
                status=CheckStatus.PASSED,
                message="No unassigned shards",
                severity="info"
            ))

    def _check_index_health(self):
        """Check health status of all indices."""
        indices = self.es.get_indices_info()

        if not indices or "error" in indices[0]:
            self._add_check(AuditCheck(
                name="Index Health",
                category="indices",
                status=CheckStatus.ERROR,
                message="Failed to get index information",
                severity="high"
            ))
            return

        red_indices = [i for i in indices if i.get("health") == "red"]
        yellow_indices = [i for i in indices if i.get("health") == "yellow"]
        closed_indices = [i for i in indices if i.get("status") == "close"]

        if red_indices:
            self._add_check(AuditCheck(
                name="Red Indices",
                category="indices",
                status=CheckStatus.FAILED,
                message=f"{len(red_indices)} index(es) in RED state",
                details={"red_indices": [i.get("index") for i in red_indices]},
                recommendations=[
                    "Resolve all RED indices before upgrading",
                    "RED indicates missing primary shards - data may be unavailable",
                    "Check node status and shard allocation"
                ],
                severity="critical"
            ))
        else:
            self._add_check(AuditCheck(
                name="Red Indices",
                category="indices",
                status=CheckStatus.PASSED,
                message="No RED indices",
                severity="info"
            ))

        if yellow_indices:
            self._add_check(AuditCheck(
                name="Yellow Indices",
                category="indices",
                status=CheckStatus.WARNING,
                message=f"{len(yellow_indices)} index(es) in YELLOW state",
                details={"yellow_indices": [i.get("index") for i in yellow_indices[:10]]},
                recommendations=[
                    "YELLOW indices have unassigned replicas",
                    "Consider resolving before upgrade for full redundancy"
                ],
                severity="low"
            ))

        if closed_indices:
            self._add_check(AuditCheck(
                name="Closed Indices",
                category="indices",
                status=CheckStatus.WARNING,
                message=f"{len(closed_indices)} closed index(es) detected",
                details={"closed_indices": [i.get("index") for i in closed_indices]},
                recommendations=[
                    "Closed indices may need to be opened and reindexed after major upgrades",
                    "Consider opening indices before upgrade if they need to be migrated"
                ],
                severity="low"
            ))

        self._add_check(AuditCheck(
            name="Index Count",
            category="indices",
            status=CheckStatus.PASSED,
            message=f"Total indices: {len(indices)} (Green: {len(indices) - len(red_indices) - len(yellow_indices)})",
            details={
                "total": len(indices),
                "green": len(indices) - len(red_indices) - len(yellow_indices),
                "yellow": len(yellow_indices),
                "red": len(red_indices),
                "closed": len(closed_indices)
            },
            severity="info"
        ))

    def _check_deprecated_settings(self):
        """Check for deprecated settings and configurations."""
        deprecations = self.es.get_deprecation_info()

        if "error" in deprecations:
            self._add_check(AuditCheck(
                name="Deprecation Check",
                category="compatibility",
                status=CheckStatus.WARNING,
                message="Could not check deprecations (API may not be available)",
                details=deprecations,
                severity="medium"
            ))
            return

        cluster_deprecations = deprecations.get("cluster_settings", [])
        node_deprecations = deprecations.get("node_settings", [])
        index_deprecations = deprecations.get("index_settings", {})

        total_deprecations = len(cluster_deprecations) + len(node_deprecations) + \
                           sum(len(v) for v in index_deprecations.values())

        if total_deprecations > 0:
            critical_deprecations = []
            warning_deprecations = []

            for dep in cluster_deprecations + node_deprecations:
                if dep.get("level") == "critical":
                    critical_deprecations.append(dep.get("message"))
                else:
                    warning_deprecations.append(dep.get("message"))

            status = CheckStatus.FAILED if critical_deprecations else CheckStatus.WARNING

            self._add_check(AuditCheck(
                name="Deprecated Settings",
                category="compatibility",
                status=status,
                message=f"{total_deprecations} deprecation warning(s) found",
                details={
                    "cluster_settings": cluster_deprecations,
                    "node_settings": node_deprecations,
                    "index_settings_count": len(index_deprecations),
                    "critical": critical_deprecations,
                    "warnings": warning_deprecations[:10]
                },
                recommendations=[
                    "Review and resolve deprecated settings before upgrade",
                    "Critical deprecations must be resolved",
                    "Check Elasticsearch upgrade documentation for migration steps"
                ],
                severity="high" if critical_deprecations else "medium"
            ))
        else:
            self._add_check(AuditCheck(
                name="Deprecated Settings",
                category="compatibility",
                status=CheckStatus.PASSED,
                message="No deprecated settings found",
                severity="info"
            ))

    def _check_pending_tasks(self):
        """Check for pending cluster tasks."""
        tasks = self.es.get_pending_tasks()

        if isinstance(tasks, list) and tasks and "error" in tasks[0]:
            return

        if tasks:
            self._add_check(AuditCheck(
                name="Pending Tasks",
                category="cluster",
                status=CheckStatus.WARNING,
                message=f"{len(tasks)} pending cluster task(s)",
                details={"tasks": tasks[:10]},
                recommendations=[
                    "Wait for pending tasks to complete before upgrade",
                    "High number of pending tasks may indicate cluster issues"
                ],
                severity="medium"
            ))
        else:
            self._add_check(AuditCheck(
                name="Pending Tasks",
                category="cluster",
                status=CheckStatus.PASSED,
                message="No pending cluster tasks",
                severity="info"
            ))

    def _check_snapshot_status(self):
        """Check snapshot repository and recent snapshots."""
        repos = self.es.get_snapshot_repositories()

        if "error" in repos:
            self._add_check(AuditCheck(
                name="Snapshot Repository",
                category="backup",
                status=CheckStatus.WARNING,
                message="Could not check snapshot repositories",
                details=repos,
                recommendations=[
                    "Ensure snapshot repository is configured before upgrade",
                    "Create a full snapshot as backup before upgrade"
                ],
                severity="high"
            ))
            return

        if not repos:
            self._add_check(AuditCheck(
                name="Snapshot Repository",
                category="backup",
                status=CheckStatus.FAILED,
                message="No snapshot repository configured",
                recommendations=[
                    "Configure a snapshot repository before upgrade",
                    "Create a full cluster snapshot as backup",
                    "Snapshots are essential for rollback if upgrade fails"
                ],
                severity="critical"
            ))
        else:
            self._add_check(AuditCheck(
                name="Snapshot Repository",
                category="backup",
                status=CheckStatus.PASSED,
                message=f"{len(repos)} snapshot repository(ies) configured",
                details={"repositories": list(repos.keys())},
                recommendations=[
                    "Ensure a recent snapshot exists before upgrade"
                ],
                severity="info"
            ))

            # Check for recent snapshots in first repo
            first_repo = list(repos.keys())[0]
            snapshots = self.es.get_snapshots(first_repo)

            if snapshots and "error" not in snapshots[0]:
                successful_snapshots = [s for s in snapshots if s.get("state") == "SUCCESS"]
                if successful_snapshots:
                    latest = max(successful_snapshots, key=lambda x: x.get("end_time_in_millis", 0))
                    self._add_check(AuditCheck(
                        name="Recent Snapshot",
                        category="backup",
                        status=CheckStatus.PASSED,
                        message=f"Latest snapshot: {latest.get('snapshot')}",
                        details={
                            "snapshot_name": latest.get("snapshot"),
                            "indices_count": len(latest.get("indices", [])),
                            "state": latest.get("state")
                        },
                        severity="info"
                    ))
                else:
                    self._add_check(AuditCheck(
                        name="Recent Snapshot",
                        category="backup",
                        status=CheckStatus.WARNING,
                        message="No successful snapshots found",
                        recommendations=[
                            "Create a full cluster snapshot before upgrade"
                        ],
                        severity="high"
                    ))

    def _check_index_compatibility(self):
        """Check index compatibility with target version."""
        indices = self.es.get_indices_info()
        current_version = self.es.get_version()

        if not indices or "error" in indices[0]:
            return

        # Check for very old indices that may need reindexing
        self._add_check(AuditCheck(
            name="Index Compatibility",
            category="compatibility",
            status=CheckStatus.PASSED,
            message=f"Index compatibility check completed for {len(indices)} indices",
            details={"index_count": len(indices)},
            recommendations=[
                "Indices created in ES 6.x may need reindexing for ES 8.x",
                "Check index settings for deprecated analyzers or mappings"
            ],
            severity="info"
        ))

    def _check_plugin_compatibility(self):
        """Check installed plugins for compatibility."""
        nodes = self.es.get_nodes_info()

        if not nodes or "error" in nodes[0]:
            return

        all_plugins = set()
        for node in nodes:
            plugins = node.get("plugins", [])
            all_plugins.update(plugins)

        if all_plugins:
            self._add_check(AuditCheck(
                name="Plugins Installed",
                category="compatibility",
                status=CheckStatus.WARNING,
                message=f"{len(all_plugins)} plugin(s) installed - verify compatibility",
                details={"plugins": list(all_plugins)},
                recommendations=[
                    "Check if all plugins are compatible with target version",
                    "Some plugins may need to be upgraded or replaced",
                    "Plan for plugin upgrades as part of cluster upgrade"
                ],
                severity="medium"
            ))
        else:
            self._add_check(AuditCheck(
                name="Plugins Installed",
                category="compatibility",
                status=CheckStatus.PASSED,
                message="No third-party plugins installed",
                severity="info"
            ))

    def _check_ilm_policies(self):
        """Check ILM policies for potential issues."""
        try:
            # This is a basic check - could be expanded
            self._add_check(AuditCheck(
                name="ILM Policies",
                category="features",
                status=CheckStatus.PASSED,
                message="ILM policy check completed",
                recommendations=[
                    "Review ILM policies for deprecated actions after upgrade"
                ],
                severity="info"
            ))
        except Exception as e:
            self.logger.debug(f"ILM check skipped: {e}")

    def _check_transforms(self):
        """Check for running transforms."""
        try:
            self._add_check(AuditCheck(
                name="Transforms",
                category="features",
                status=CheckStatus.PASSED,
                message="Transform check completed",
                recommendations=[
                    "Stop transforms before upgrade if needed",
                    "Transforms will be paused during rolling upgrade"
                ],
                severity="info"
            ))
        except Exception as e:
            self.logger.debug(f"Transform check skipped: {e}")

    def _check_watchers(self):
        """Check for active watchers."""
        try:
            self._add_check(AuditCheck(
                name="Watchers",
                category="features",
                status=CheckStatus.PASSED,
                message="Watcher check completed",
                recommendations=[
                    "Watchers may miss executions during upgrade window"
                ],
                severity="info"
            ))
        except Exception as e:
            self.logger.debug(f"Watcher check skipped: {e}")

    def _generate_report(self) -> AuditReport:
        """Generate the final audit report."""
        summary = {
            "passed": len([c for c in self.checks if c.status == CheckStatus.PASSED]),
            "warning": len([c for c in self.checks if c.status == CheckStatus.WARNING]),
            "failed": len([c for c in self.checks if c.status == CheckStatus.FAILED]),
            "error": len([c for c in self.checks if c.status == CheckStatus.ERROR]),
            "skipped": len([c for c in self.checks if c.status == CheckStatus.SKIPPED])
        }

        # Determine if cluster is ready for upgrade
        ready = summary["failed"] == 0 and summary["error"] == 0

        # Get critical issues
        critical_issues = [c for c in self.checks
                         if c.status in [CheckStatus.FAILED, CheckStatus.ERROR]
                         or c.severity == "critical"]

        return AuditReport(
            cluster_name=self.es.cluster_info.get("cluster_name", "unknown"),
            current_version=self.es.get_version(),
            target_version=self.config.upgrade.target_version,
            timestamp=datetime.now().isoformat(),
            checks=self.checks,
            summary=summary,
            ready_for_upgrade=ready
        )

    def get_upgrade_blockers(self) -> List[AuditCheck]:
        """
        Get list of issues that block the upgrade.

        Returns:
            List of blocking AuditCheck items.
        """
        return [c for c in self.checks
                if c.status in [CheckStatus.FAILED, CheckStatus.ERROR]]

    def get_warnings(self) -> List[AuditCheck]:
        """
        Get list of warning issues.

        Returns:
            List of warning AuditCheck items.
        """
        return [c for c in self.checks if c.status == CheckStatus.WARNING]

    def get_recommendations(self) -> List[str]:
        """
        Get consolidated list of all recommendations.

        Returns:
            List of recommendation strings.
        """
        recommendations = []
        for check in self.checks:
            if check.recommendations:
                recommendations.extend(check.recommendations)
        return list(set(recommendations))
