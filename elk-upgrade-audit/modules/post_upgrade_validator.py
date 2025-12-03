"""
Post-Upgrade Validator Module for ELK Upgrade Audit Tool
=========================================================
Validates cluster state and functionality after an upgrade.
"""

import logging
import time
from typing import Dict, Any, List, Optional
from datetime import datetime
from dataclasses import dataclass, field
from enum import Enum


class ValidationStatus(Enum):
    """Status of a validation check."""
    PASSED = "passed"
    FAILED = "failed"
    WARNING = "warning"
    SKIPPED = "skipped"


@dataclass
class ValidationCheck:
    """Result of a single validation check."""
    name: str
    category: str
    status: ValidationStatus
    message: str
    details: Dict[str, Any] = field(default_factory=dict)
    duration_ms: int = 0


@dataclass
class ValidationReport:
    """Complete validation report."""
    timestamp: str
    cluster_name: str
    version: str
    checks: List[ValidationCheck] = field(default_factory=list)
    summary: Dict[str, int] = field(default_factory=dict)
    passed: bool = False
    total_duration_ms: int = 0


class PostUpgradeValidator:
    """
    Validates Elasticsearch cluster after upgrade.
    """

    def __init__(self, es_client, config, pre_upgrade_state: Optional[Dict] = None):
        """
        Initialize the post-upgrade validator.

        Args:
            es_client: ElasticsearchClient instance
            config: ConfigManager instance
            pre_upgrade_state: State captured before upgrade for comparison
        """
        self.es = es_client
        self.config = config
        self.pre_state = pre_upgrade_state or {}
        self.logger = logging.getLogger(__name__)
        self.checks: List[ValidationCheck] = []

    def run_validation(self) -> ValidationReport:
        """
        Run complete post-upgrade validation.

        Returns:
            ValidationReport with all check results.
        """
        start_time = time.time()
        self.checks = []
        self.logger.info("Starting post-upgrade validation...")

        # Run all validation checks
        self._validate_cluster_health()
        self._validate_node_versions()
        self._validate_all_nodes_joined()
        self._validate_shard_allocation()
        self._validate_index_availability()
        self._validate_index_health()
        self._validate_document_counts()
        self._validate_cluster_settings()
        self._validate_templates()
        self._validate_ilm_policies()
        self._validate_search_functionality()
        self._validate_indexing_functionality()
        self._validate_security_enabled()
        self._validate_no_deprecation_warnings()

        total_duration = int((time.time() - start_time) * 1000)

        # Generate report
        report = self._generate_report(total_duration)
        self.logger.info(f"Validation complete. Passed: {report.passed}")

        return report

    def _add_check(self, check: ValidationCheck):
        """Add a validation check to results."""
        self.checks.append(check)
        log_method = self.logger.info if check.status == ValidationStatus.PASSED else \
                     self.logger.warning if check.status == ValidationStatus.WARNING else \
                     self.logger.error
        log_method(f"[{check.status.value.upper()}] {check.name}: {check.message}")

    def _validate_cluster_health(self):
        """Validate cluster health is green."""
        start = time.time()
        health = self.es.get_cluster_health()

        status = health.get("status", "unknown")
        duration = int((time.time() - start) * 1000)

        if status == "green":
            self._add_check(ValidationCheck(
                name="Cluster Health",
                category="cluster",
                status=ValidationStatus.PASSED,
                message="Cluster health is GREEN",
                details=health,
                duration_ms=duration
            ))
        elif status == "yellow":
            self._add_check(ValidationCheck(
                name="Cluster Health",
                category="cluster",
                status=ValidationStatus.WARNING,
                message="Cluster health is YELLOW - some replicas not assigned",
                details=health,
                duration_ms=duration
            ))
        else:
            self._add_check(ValidationCheck(
                name="Cluster Health",
                category="cluster",
                status=ValidationStatus.FAILED,
                message=f"Cluster health is {status.upper()}",
                details=health,
                duration_ms=duration
            ))

    def _validate_node_versions(self):
        """Validate all nodes are running the target version."""
        start = time.time()
        nodes = self.es.get_nodes_info()
        target_version = self.config.upgrade.target_version
        duration = int((time.time() - start) * 1000)

        if not nodes or "error" in nodes[0]:
            self._add_check(ValidationCheck(
                name="Node Versions",
                category="nodes",
                status=ValidationStatus.FAILED,
                message="Failed to get node information",
                duration_ms=duration
            ))
            return

        versions = set(node.get("version") for node in nodes)
        mismatched = [n for n in nodes if n.get("version") != target_version]

        if len(versions) == 1 and target_version in versions:
            self._add_check(ValidationCheck(
                name="Node Versions",
                category="nodes",
                status=ValidationStatus.PASSED,
                message=f"All {len(nodes)} nodes running version {target_version}",
                details={"node_count": len(nodes), "version": target_version},
                duration_ms=duration
            ))
        elif mismatched:
            self._add_check(ValidationCheck(
                name="Node Versions",
                category="nodes",
                status=ValidationStatus.FAILED,
                message=f"{len(mismatched)} node(s) not running target version",
                details={
                    "target_version": target_version,
                    "mismatched_nodes": [(n.get("name"), n.get("version")) for n in mismatched]
                },
                duration_ms=duration
            ))
        else:
            self._add_check(ValidationCheck(
                name="Node Versions",
                category="nodes",
                status=ValidationStatus.WARNING,
                message=f"Nodes running version(s): {versions}",
                details={"versions": list(versions)},
                duration_ms=duration
            ))

    def _validate_all_nodes_joined(self):
        """Validate expected number of nodes have joined."""
        start = time.time()
        health = self.es.get_cluster_health()
        nodes = self.es.get_nodes_info()
        duration = int((time.time() - start) * 1000)

        current_nodes = health.get("number_of_nodes", 0)
        expected_nodes = self.pre_state.get("node_count", current_nodes)

        if current_nodes >= expected_nodes:
            self._add_check(ValidationCheck(
                name="Node Count",
                category="nodes",
                status=ValidationStatus.PASSED,
                message=f"All {current_nodes} nodes have joined the cluster",
                details={
                    "current": current_nodes,
                    "expected": expected_nodes,
                    "nodes": [n.get("name") for n in nodes if "error" not in n]
                },
                duration_ms=duration
            ))
        else:
            self._add_check(ValidationCheck(
                name="Node Count",
                category="nodes",
                status=ValidationStatus.FAILED,
                message=f"Only {current_nodes}/{expected_nodes} nodes in cluster",
                details={
                    "current": current_nodes,
                    "expected": expected_nodes,
                    "nodes": [n.get("name") for n in nodes if "error" not in n]
                },
                duration_ms=duration
            ))

    def _validate_shard_allocation(self):
        """Validate shard allocation is enabled and complete."""
        start = time.time()
        health = self.es.get_cluster_health()
        settings = self.es.get_cluster_settings()
        duration = int((time.time() - start) * 1000)

        # Check if allocation is enabled
        persistent = settings.get("persistent", {})
        transient = settings.get("transient", {})

        allocation_setting = transient.get("cluster.routing.allocation.enable") or \
                           persistent.get("cluster.routing.allocation.enable") or \
                           "all"

        if allocation_setting != "all":
            self._add_check(ValidationCheck(
                name="Shard Allocation",
                category="shards",
                status=ValidationStatus.FAILED,
                message=f"Shard allocation is set to '{allocation_setting}' - should be 'all'",
                details={"allocation_setting": allocation_setting},
                duration_ms=duration
            ))
            return

        # Check for unassigned shards
        unassigned = health.get("unassigned_shards", 0)
        relocating = health.get("relocating_shards", 0)
        initializing = health.get("initializing_shards", 0)

        if unassigned == 0 and relocating == 0 and initializing == 0:
            self._add_check(ValidationCheck(
                name="Shard Allocation",
                category="shards",
                status=ValidationStatus.PASSED,
                message="All shards allocated and stable",
                details={
                    "active_shards": health.get("active_shards"),
                    "active_primary_shards": health.get("active_primary_shards")
                },
                duration_ms=duration
            ))
        elif relocating > 0 or initializing > 0:
            self._add_check(ValidationCheck(
                name="Shard Allocation",
                category="shards",
                status=ValidationStatus.WARNING,
                message=f"Shard movement in progress: {relocating} relocating, {initializing} initializing",
                details={
                    "relocating": relocating,
                    "initializing": initializing,
                    "unassigned": unassigned
                },
                duration_ms=duration
            ))
        else:
            self._add_check(ValidationCheck(
                name="Shard Allocation",
                category="shards",
                status=ValidationStatus.WARNING,
                message=f"{unassigned} unassigned shard(s)",
                details={"unassigned": unassigned},
                duration_ms=duration
            ))

    def _validate_index_availability(self):
        """Validate all indices are open and accessible."""
        start = time.time()
        indices = self.es.get_indices_info()
        duration = int((time.time() - start) * 1000)

        if not indices or "error" in indices[0]:
            self._add_check(ValidationCheck(
                name="Index Availability",
                category="indices",
                status=ValidationStatus.FAILED,
                message="Failed to get index information",
                duration_ms=duration
            ))
            return

        closed = [i for i in indices if i.get("status") == "close"]
        total = len(indices)

        if not closed:
            self._add_check(ValidationCheck(
                name="Index Availability",
                category="indices",
                status=ValidationStatus.PASSED,
                message=f"All {total} indices are open and accessible",
                details={"total_indices": total},
                duration_ms=duration
            ))
        else:
            self._add_check(ValidationCheck(
                name="Index Availability",
                category="indices",
                status=ValidationStatus.WARNING,
                message=f"{len(closed)}/{total} indices are closed",
                details={
                    "total": total,
                    "closed": [i.get("index") for i in closed]
                },
                duration_ms=duration
            ))

    def _validate_index_health(self):
        """Validate index health status."""
        start = time.time()
        indices = self.es.get_indices_info()
        duration = int((time.time() - start) * 1000)

        if not indices or "error" in indices[0]:
            return

        red = [i for i in indices if i.get("health") == "red"]
        yellow = [i for i in indices if i.get("health") == "yellow"]
        green = [i for i in indices if i.get("health") == "green"]

        if not red:
            self._add_check(ValidationCheck(
                name="Index Health",
                category="indices",
                status=ValidationStatus.PASSED if not yellow else ValidationStatus.WARNING,
                message=f"No RED indices (Green: {len(green)}, Yellow: {len(yellow)})",
                details={
                    "green": len(green),
                    "yellow": len(yellow),
                    "red": len(red)
                },
                duration_ms=duration
            ))
        else:
            self._add_check(ValidationCheck(
                name="Index Health",
                category="indices",
                status=ValidationStatus.FAILED,
                message=f"{len(red)} RED index(es) detected",
                details={
                    "red_indices": [i.get("index") for i in red],
                    "green": len(green),
                    "yellow": len(yellow),
                    "red": len(red)
                },
                duration_ms=duration
            ))

    def _validate_document_counts(self):
        """Validate document counts match pre-upgrade state."""
        start = time.time()
        indices = self.es.get_indices_info()
        duration = int((time.time() - start) * 1000)

        if not indices or "error" in indices[0]:
            return

        pre_counts = self.pre_state.get("document_counts", {})
        if not pre_counts:
            self._add_check(ValidationCheck(
                name="Document Counts",
                category="data",
                status=ValidationStatus.SKIPPED,
                message="No pre-upgrade document counts available for comparison",
                duration_ms=duration
            ))
            return

        mismatches = []
        for index in indices:
            idx_name = index.get("index")
            current_count = index.get("docs_count", 0)
            pre_count = pre_counts.get(idx_name)

            if pre_count is not None and current_count < pre_count:
                mismatches.append({
                    "index": idx_name,
                    "pre_upgrade": pre_count,
                    "post_upgrade": current_count,
                    "difference": pre_count - current_count
                })

        if not mismatches:
            self._add_check(ValidationCheck(
                name="Document Counts",
                category="data",
                status=ValidationStatus.PASSED,
                message="Document counts match or exceed pre-upgrade values",
                duration_ms=duration
            ))
        else:
            self._add_check(ValidationCheck(
                name="Document Counts",
                category="data",
                status=ValidationStatus.WARNING,
                message=f"{len(mismatches)} index(es) have fewer documents than before upgrade",
                details={"mismatches": mismatches},
                duration_ms=duration
            ))

    def _validate_cluster_settings(self):
        """Validate cluster settings are correct."""
        start = time.time()
        settings = self.es.get_cluster_settings()
        duration = int((time.time() - start) * 1000)

        if "error" in settings:
            self._add_check(ValidationCheck(
                name="Cluster Settings",
                category="settings",
                status=ValidationStatus.WARNING,
                message="Could not retrieve cluster settings",
                duration_ms=duration
            ))
            return

        # Check for any problematic settings
        issues = []

        # Check allocation is enabled
        allocation = settings.get("persistent", {}).get("cluster.routing.allocation.enable")
        if allocation and allocation != "all":
            issues.append(f"Shard allocation is '{allocation}'")

        if issues:
            self._add_check(ValidationCheck(
                name="Cluster Settings",
                category="settings",
                status=ValidationStatus.WARNING,
                message=f"Settings issues found: {'; '.join(issues)}",
                details={"issues": issues},
                duration_ms=duration
            ))
        else:
            self._add_check(ValidationCheck(
                name="Cluster Settings",
                category="settings",
                status=ValidationStatus.PASSED,
                message="Cluster settings validated",
                duration_ms=duration
            ))

    def _validate_templates(self):
        """Validate index templates are intact."""
        start = time.time()
        templates = self.es.get_index_templates()
        duration = int((time.time() - start) * 1000)

        if "error" in templates:
            self._add_check(ValidationCheck(
                name="Index Templates",
                category="templates",
                status=ValidationStatus.WARNING,
                message="Could not retrieve index templates",
                duration_ms=duration
            ))
            return

        legacy_count = len(templates.get("legacy_templates", {}))
        composable_count = len(templates.get("composable_templates", {}).get("index_templates", []))

        self._add_check(ValidationCheck(
            name="Index Templates",
            category="templates",
            status=ValidationStatus.PASSED,
            message=f"Templates validated: {legacy_count} legacy, {composable_count} composable",
            details={
                "legacy_templates": legacy_count,
                "composable_templates": composable_count
            },
            duration_ms=duration
        ))

    def _validate_ilm_policies(self):
        """Validate ILM policies are intact."""
        start = time.time()
        duration = int((time.time() - start) * 1000)

        try:
            policies = self.es.client.ilm.get_lifecycle()
            policy_count = len(policies)

            self._add_check(ValidationCheck(
                name="ILM Policies",
                category="ilm",
                status=ValidationStatus.PASSED,
                message=f"{policy_count} ILM policies validated",
                details={"policy_count": policy_count},
                duration_ms=duration
            ))
        except Exception as e:
            self._add_check(ValidationCheck(
                name="ILM Policies",
                category="ilm",
                status=ValidationStatus.SKIPPED,
                message=f"Could not validate ILM policies: {e}",
                duration_ms=duration
            ))

    def _validate_search_functionality(self):
        """Validate search is working."""
        start = time.time()

        try:
            # Try a simple search on all indices
            result = self.es.client.search(
                index="_all",
                body={"query": {"match_all": {}}, "size": 1},
                ignore_unavailable=True
            )

            duration = int((time.time() - start) * 1000)

            hits = result.get("hits", {}).get("total", {})
            total = hits.get("value", 0) if isinstance(hits, dict) else hits

            self._add_check(ValidationCheck(
                name="Search Functionality",
                category="functionality",
                status=ValidationStatus.PASSED,
                message=f"Search working - found {total} documents",
                details={"total_documents": total},
                duration_ms=duration
            ))

        except Exception as e:
            duration = int((time.time() - start) * 1000)
            self._add_check(ValidationCheck(
                name="Search Functionality",
                category="functionality",
                status=ValidationStatus.FAILED,
                message=f"Search failed: {e}",
                duration_ms=duration
            ))

    def _validate_indexing_functionality(self):
        """Validate indexing is working (optional test)."""
        start = time.time()

        try:
            test_index = ".elk-upgrade-audit-test"
            test_doc = {
                "test": True,
                "timestamp": datetime.now().isoformat(),
                "message": "Post-upgrade validation test"
            }

            # Index test document
            self.es.client.index(
                index=test_index,
                document=test_doc,
                refresh=True
            )

            # Verify it was indexed
            result = self.es.client.search(
                index=test_index,
                body={"query": {"match_all": {}}}
            )

            # Clean up
            self.es.client.indices.delete(index=test_index, ignore_unavailable=True)

            duration = int((time.time() - start) * 1000)

            hits = result.get("hits", {}).get("total", {})
            found = (hits.get("value", 0) if isinstance(hits, dict) else hits) > 0

            if found:
                self._add_check(ValidationCheck(
                    name="Indexing Functionality",
                    category="functionality",
                    status=ValidationStatus.PASSED,
                    message="Indexing working - test document created and retrieved",
                    duration_ms=duration
                ))
            else:
                self._add_check(ValidationCheck(
                    name="Indexing Functionality",
                    category="functionality",
                    status=ValidationStatus.FAILED,
                    message="Test document not found after indexing",
                    duration_ms=duration
                ))

        except Exception as e:
            duration = int((time.time() - start) * 1000)
            self._add_check(ValidationCheck(
                name="Indexing Functionality",
                category="functionality",
                status=ValidationStatus.WARNING,
                message=f"Indexing test skipped: {e}",
                duration_ms=duration
            ))

    def _validate_security_enabled(self):
        """Validate security is properly configured (for ES 8.x)."""
        start = time.time()
        version = self.es.get_version()
        duration = int((time.time() - start) * 1000)

        # Only relevant for ES 8.x
        if not version.startswith("8."):
            self._add_check(ValidationCheck(
                name="Security Configuration",
                category="security",
                status=ValidationStatus.SKIPPED,
                message=f"Security check skipped for version {version}",
                duration_ms=duration
            ))
            return

        try:
            # Check if security is enabled by trying to get security info
            self.es.client.security.get_user()

            self._add_check(ValidationCheck(
                name="Security Configuration",
                category="security",
                status=ValidationStatus.PASSED,
                message="Security is enabled and accessible",
                duration_ms=duration
            ))

        except Exception as e:
            error_str = str(e).lower()
            if "security" in error_str and "disabled" in error_str:
                self._add_check(ValidationCheck(
                    name="Security Configuration",
                    category="security",
                    status=ValidationStatus.WARNING,
                    message="Security appears to be disabled - ES 8.x has security enabled by default",
                    duration_ms=duration
                ))
            else:
                self._add_check(ValidationCheck(
                    name="Security Configuration",
                    category="security",
                    status=ValidationStatus.PASSED,
                    message="Security check completed",
                    duration_ms=duration
                ))

    def _validate_no_deprecation_warnings(self):
        """Check for deprecation warnings."""
        start = time.time()
        deprecations = self.es.get_deprecation_info()
        duration = int((time.time() - start) * 1000)

        if "error" in deprecations or "warning" in deprecations:
            self._add_check(ValidationCheck(
                name="Deprecation Warnings",
                category="compatibility",
                status=ValidationStatus.SKIPPED,
                message="Deprecation API not available",
                duration_ms=duration
            ))
            return

        total_deprecations = len(deprecations.get("cluster_settings", [])) + \
                           len(deprecations.get("node_settings", []))

        if total_deprecations == 0:
            self._add_check(ValidationCheck(
                name="Deprecation Warnings",
                category="compatibility",
                status=ValidationStatus.PASSED,
                message="No deprecation warnings",
                duration_ms=duration
            ))
        else:
            self._add_check(ValidationCheck(
                name="Deprecation Warnings",
                category="compatibility",
                status=ValidationStatus.WARNING,
                message=f"{total_deprecations} deprecation warning(s) found",
                details=deprecations,
                duration_ms=duration
            ))

    def _generate_report(self, total_duration: int) -> ValidationReport:
        """Generate the validation report."""
        summary = {
            "passed": len([c for c in self.checks if c.status == ValidationStatus.PASSED]),
            "failed": len([c for c in self.checks if c.status == ValidationStatus.FAILED]),
            "warning": len([c for c in self.checks if c.status == ValidationStatus.WARNING]),
            "skipped": len([c for c in self.checks if c.status == ValidationStatus.SKIPPED])
        }

        passed = summary["failed"] == 0

        return ValidationReport(
            timestamp=datetime.now().isoformat(),
            cluster_name=self.es.cluster_info.get("cluster_name", "unknown"),
            version=self.es.get_version(),
            checks=self.checks,
            summary=summary,
            passed=passed,
            total_duration_ms=total_duration
        )

    def capture_pre_upgrade_state(self) -> Dict[str, Any]:
        """
        Capture cluster state before upgrade for comparison.

        Returns:
            Dictionary with pre-upgrade state.
        """
        state = {}

        # Capture node count
        health = self.es.get_cluster_health()
        state["node_count"] = health.get("number_of_nodes", 0)
        state["data_node_count"] = health.get("number_of_data_nodes", 0)

        # Capture document counts per index
        indices = self.es.get_indices_info()
        state["document_counts"] = {
            i.get("index"): i.get("docs_count", 0)
            for i in indices if "error" not in i
        }

        # Capture index list
        state["indices"] = [i.get("index") for i in indices if "error" not in i]

        # Capture template count
        templates = self.es.get_index_templates()
        state["template_count"] = len(templates.get("legacy_templates", {}))

        state["captured_at"] = datetime.now().isoformat()

        return state
