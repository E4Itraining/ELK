"""
Upgrade Orchestrator Module for ELK Upgrade Audit Tool
======================================================
Orchestrates the different phases of an Elasticsearch cluster upgrade.
"""

import logging
import time
from typing import Dict, Any, List, Optional, Callable
from datetime import datetime
from dataclasses import dataclass, field
from enum import Enum


class UpgradePhase(Enum):
    """Phases of the upgrade process."""
    NOT_STARTED = "not_started"
    PRE_CHECKS = "pre_checks"
    BACKUP = "backup"
    DISABLE_ALLOCATION = "disable_allocation"
    STOP_INDEXING = "stop_indexing"
    SYNC_FLUSH = "sync_flush"
    NODE_UPGRADE = "node_upgrade"
    ENABLE_ALLOCATION = "enable_allocation"
    WAIT_RECOVERY = "wait_recovery"
    POST_CHECKS = "post_checks"
    COMPLETED = "completed"
    FAILED = "failed"
    ROLLED_BACK = "rolled_back"


class NodeRole(Enum):
    """Elasticsearch node roles."""
    MASTER = "master"
    DATA = "data"
    INGEST = "ingest"
    COORDINATING = "coordinating"
    ML = "ml"


@dataclass
class UpgradeStep:
    """Represents a single upgrade step."""
    phase: UpgradePhase
    description: str
    started_at: Optional[str] = None
    completed_at: Optional[str] = None
    status: str = "pending"  # pending, in_progress, completed, failed, skipped
    result: Dict[str, Any] = field(default_factory=dict)
    error: Optional[str] = None


@dataclass
class NodeUpgradeStatus:
    """Status of a node upgrade."""
    node_id: str
    node_name: str
    old_version: str
    new_version: Optional[str] = None
    status: str = "pending"  # pending, upgrading, completed, failed
    started_at: Optional[str] = None
    completed_at: Optional[str] = None
    error: Optional[str] = None


@dataclass
class UpgradeState:
    """Overall upgrade state."""
    upgrade_id: str
    started_at: str
    current_phase: UpgradePhase
    target_version: str
    strategy: str
    steps: List[UpgradeStep] = field(default_factory=list)
    nodes: List[NodeUpgradeStatus] = field(default_factory=list)
    rollback_available: bool = True
    completed_at: Optional[str] = None
    error: Optional[str] = None


class UpgradeOrchestrator:
    """
    Orchestrates Elasticsearch cluster upgrade process.
    Supports both rolling upgrade and full cluster restart strategies.
    """

    # Recommended order for node upgrades
    NODE_UPGRADE_ORDER = [
        NodeRole.COORDINATING,
        NodeRole.INGEST,
        NodeRole.DATA,
        NodeRole.MASTER
    ]

    def __init__(self, es_client, config, snapshot_manager=None,
                 pre_upgrade_audit=None, post_upgrade_validator=None):
        """
        Initialize the upgrade orchestrator.

        Args:
            es_client: ElasticsearchClient instance
            config: ConfigManager instance
            snapshot_manager: SnapshotManager instance (optional)
            pre_upgrade_audit: PreUpgradeAudit instance (optional)
            post_upgrade_validator: PostUpgradeValidator instance (optional)
        """
        self.es = es_client
        self.config = config
        self.snapshot_manager = snapshot_manager
        self.pre_audit = pre_upgrade_audit
        self.post_validator = post_upgrade_validator
        self.logger = logging.getLogger(__name__)
        self.state: Optional[UpgradeState] = None
        self.callbacks: Dict[str, List[Callable]] = {
            "phase_start": [],
            "phase_complete": [],
            "node_start": [],
            "node_complete": [],
            "error": []
        }

    def register_callback(self, event: str, callback: Callable):
        """Register a callback for upgrade events."""
        if event in self.callbacks:
            self.callbacks[event].append(callback)

    def _emit_event(self, event: str, data: Dict[str, Any]):
        """Emit an event to registered callbacks."""
        for callback in self.callbacks.get(event, []):
            try:
                callback(data)
            except Exception as e:
                self.logger.error(f"Callback error: {e}")

    def initialize_upgrade(self) -> UpgradeState:
        """
        Initialize the upgrade state and plan.

        Returns:
            UpgradeState object with the upgrade plan.
        """
        upgrade_id = f"upgrade-{datetime.now().strftime('%Y%m%d-%H%M%S')}"

        # Get current nodes
        nodes_info = self.es.get_nodes_info()
        nodes = []

        for node in nodes_info:
            if "error" not in node:
                nodes.append(NodeUpgradeStatus(
                    node_id=node.get("node_id"),
                    node_name=node.get("name"),
                    old_version=node.get("version"),
                    status="pending"
                ))

        # Create upgrade steps based on strategy
        steps = self._create_upgrade_steps()

        self.state = UpgradeState(
            upgrade_id=upgrade_id,
            started_at=datetime.now().isoformat(),
            current_phase=UpgradePhase.NOT_STARTED,
            target_version=self.config.upgrade.target_version,
            strategy=self.config.upgrade.strategy,
            steps=steps,
            nodes=nodes,
            rollback_available=True
        )

        self.logger.info(f"Initialized upgrade: {upgrade_id}")
        return self.state

    def _create_upgrade_steps(self) -> List[UpgradeStep]:
        """Create the list of upgrade steps based on strategy."""
        steps = [
            UpgradeStep(
                phase=UpgradePhase.PRE_CHECKS,
                description="Run pre-upgrade health checks"
            ),
            UpgradeStep(
                phase=UpgradePhase.BACKUP,
                description="Create pre-upgrade snapshot backup"
            ),
            UpgradeStep(
                phase=UpgradePhase.DISABLE_ALLOCATION,
                description="Disable shard allocation"
            ),
            UpgradeStep(
                phase=UpgradePhase.STOP_INDEXING,
                description="Stop non-essential indexing"
            ),
            UpgradeStep(
                phase=UpgradePhase.SYNC_FLUSH,
                description="Perform sync flush on all indices"
            ),
            UpgradeStep(
                phase=UpgradePhase.NODE_UPGRADE,
                description="Upgrade cluster nodes"
            ),
            UpgradeStep(
                phase=UpgradePhase.ENABLE_ALLOCATION,
                description="Re-enable shard allocation"
            ),
            UpgradeStep(
                phase=UpgradePhase.WAIT_RECOVERY,
                description="Wait for cluster recovery"
            ),
            UpgradeStep(
                phase=UpgradePhase.POST_CHECKS,
                description="Run post-upgrade validation"
            )
        ]

        return steps

    def get_upgrade_plan(self) -> Dict[str, Any]:
        """
        Get the detailed upgrade plan.

        Returns:
            Dictionary with the upgrade plan details.
        """
        if not self.state:
            self.initialize_upgrade()

        plan = {
            "upgrade_id": self.state.upgrade_id,
            "strategy": self.state.strategy,
            "target_version": self.state.target_version,
            "node_count": len(self.state.nodes),
            "phases": []
        }

        for step in self.state.steps:
            plan["phases"].append({
                "phase": step.phase.value,
                "description": step.description,
                "status": step.status
            })

        plan["node_upgrade_order"] = self._get_node_upgrade_order()

        return plan

    def _get_node_upgrade_order(self) -> List[Dict[str, Any]]:
        """Get the recommended order for upgrading nodes."""
        if not self.state:
            return []

        nodes_info = self.es.get_nodes_info()
        ordered_nodes = []

        # Group nodes by role
        nodes_by_role = {role: [] for role in NodeRole}

        for node_status in self.state.nodes:
            node_info = next(
                (n for n in nodes_info if n.get("node_id") == node_status.node_id),
                {}
            )
            roles = node_info.get("roles", [])

            # Determine primary role
            if "master" in roles and not any(r in roles for r in ["data", "ingest"]):
                nodes_by_role[NodeRole.MASTER].append(node_status)
            elif "data" in roles:
                nodes_by_role[NodeRole.DATA].append(node_status)
            elif "ingest" in roles:
                nodes_by_role[NodeRole.INGEST].append(node_status)
            else:
                nodes_by_role[NodeRole.COORDINATING].append(node_status)

        # Order by role priority
        for role in self.NODE_UPGRADE_ORDER:
            for node in nodes_by_role[role]:
                ordered_nodes.append({
                    "node_id": node.node_id,
                    "node_name": node.node_name,
                    "role": role.value,
                    "version": node.old_version
                })

        return ordered_nodes

    def execute_phase(self, phase: UpgradePhase) -> Dict[str, Any]:
        """
        Execute a specific upgrade phase.

        Args:
            phase: The phase to execute.

        Returns:
            Dictionary with phase execution result.
        """
        if not self.state:
            return {"error": "Upgrade not initialized"}

        step = next((s for s in self.state.steps if s.phase == phase), None)
        if not step:
            return {"error": f"Phase {phase.value} not found"}

        self.logger.info(f"Executing phase: {phase.value}")
        step.status = "in_progress"
        step.started_at = datetime.now().isoformat()
        self.state.current_phase = phase

        self._emit_event("phase_start", {
            "phase": phase.value,
            "description": step.description
        })

        try:
            result = self._execute_phase_action(phase)
            step.result = result

            if result.get("success", True):
                step.status = "completed"
                step.completed_at = datetime.now().isoformat()
                self._emit_event("phase_complete", {
                    "phase": phase.value,
                    "result": result
                })
            else:
                step.status = "failed"
                step.error = result.get("error")
                self._emit_event("error", {
                    "phase": phase.value,
                    "error": step.error
                })

            return result

        except Exception as e:
            step.status = "failed"
            step.error = str(e)
            self.logger.error(f"Phase {phase.value} failed: {e}")
            self._emit_event("error", {
                "phase": phase.value,
                "error": str(e)
            })
            return {"success": False, "error": str(e)}

    def _execute_phase_action(self, phase: UpgradePhase) -> Dict[str, Any]:
        """Execute the action for a specific phase."""
        actions = {
            UpgradePhase.PRE_CHECKS: self._run_pre_checks,
            UpgradePhase.BACKUP: self._create_backup,
            UpgradePhase.DISABLE_ALLOCATION: self._disable_allocation,
            UpgradePhase.STOP_INDEXING: self._stop_indexing,
            UpgradePhase.SYNC_FLUSH: self._sync_flush,
            UpgradePhase.NODE_UPGRADE: self._upgrade_nodes,
            UpgradePhase.ENABLE_ALLOCATION: self._enable_allocation,
            UpgradePhase.WAIT_RECOVERY: self._wait_recovery,
            UpgradePhase.POST_CHECKS: self._run_post_checks
        }

        action = actions.get(phase)
        if action:
            return action()
        return {"success": True, "message": f"No action for phase {phase.value}"}

    def _run_pre_checks(self) -> Dict[str, Any]:
        """Run pre-upgrade checks."""
        if self.pre_audit:
            report = self.pre_audit.run_full_audit()
            return {
                "success": report.ready_for_upgrade,
                "checks_passed": report.summary.get("passed", 0),
                "checks_failed": report.summary.get("failed", 0),
                "checks_warning": report.summary.get("warning", 0),
                "blockers": [c.message for c in self.pre_audit.get_upgrade_blockers()]
            }
        return {"success": True, "message": "Pre-checks skipped (no auditor configured)"}

    def _create_backup(self) -> Dict[str, Any]:
        """Create pre-upgrade backup."""
        if self.snapshot_manager:
            result = self.snapshot_manager.create_pre_upgrade_snapshot(
                wait_for_completion=True
            )
            return result
        return {"success": True, "message": "Backup skipped (no snapshot manager configured)"}

    def _disable_allocation(self) -> Dict[str, Any]:
        """Disable shard allocation."""
        success = self.es.disable_shard_allocation()
        return {
            "success": success,
            "message": "Shard allocation disabled" if success else "Failed to disable allocation"
        }

    def _stop_indexing(self) -> Dict[str, Any]:
        """Stop non-essential indexing (advisory step)."""
        return {
            "success": True,
            "message": "Indexing stop is advisory - ensure clients have stopped sending data",
            "advisory": True
        }

    def _sync_flush(self) -> Dict[str, Any]:
        """Perform sync flush."""
        success = self.es.flush_synced()
        return {
            "success": success,
            "message": "Sync flush completed" if success else "Sync flush failed"
        }

    def _upgrade_nodes(self) -> Dict[str, Any]:
        """
        Coordinate node upgrades (manual process with guidance).
        """
        upgrade_order = self._get_node_upgrade_order()

        return {
            "success": True,
            "message": "Node upgrade is a manual process",
            "instructions": [
                "Upgrade nodes in the following order:",
                *[f"  {i+1}. {n['node_name']} ({n['role']})" for i, n in enumerate(upgrade_order)],
                "",
                "For each node:",
                "  1. Stop Elasticsearch on the node",
                "  2. Upgrade Elasticsearch package/binaries",
                "  3. Update configuration if needed",
                "  4. Start Elasticsearch",
                "  5. Wait for node to rejoin cluster",
                "  6. Verify node version in cluster",
                "",
                "Use the wait_for_node command to monitor node rejoin"
            ],
            "node_order": upgrade_order
        }

    def _enable_allocation(self) -> Dict[str, Any]:
        """Re-enable shard allocation."""
        success = self.es.enable_shard_allocation()
        return {
            "success": success,
            "message": "Shard allocation enabled" if success else "Failed to enable allocation"
        }

    def _wait_recovery(self) -> Dict[str, Any]:
        """Wait for cluster recovery."""
        return self.wait_for_green_health(timeout=600)

    def _run_post_checks(self) -> Dict[str, Any]:
        """Run post-upgrade validation."""
        if self.post_validator:
            result = self.post_validator.run_validation()
            return result
        return {"success": True, "message": "Post-checks skipped (no validator configured)"}

    def wait_for_green_health(self, timeout: int = 300) -> Dict[str, Any]:
        """
        Wait for cluster health to become green.

        Args:
            timeout: Maximum wait time in seconds.

        Returns:
            Dictionary with result.
        """
        self.logger.info(f"Waiting for cluster health to be GREEN (timeout: {timeout}s)")
        start_time = time.time()

        while time.time() - start_time < timeout:
            health = self.es.get_cluster_health()
            status = health.get("status")

            if status == "green":
                return {
                    "success": True,
                    "status": status,
                    "message": "Cluster health is GREEN",
                    "wait_time": int(time.time() - start_time)
                }

            self.logger.info(f"Cluster status: {status}, waiting...")
            time.sleep(10)

        return {
            "success": False,
            "status": health.get("status"),
            "message": f"Timeout waiting for GREEN health after {timeout}s"
        }

    def wait_for_node(self, node_name: str, expected_version: str,
                      timeout: int = 300) -> Dict[str, Any]:
        """
        Wait for a specific node to rejoin with expected version.

        Args:
            node_name: Name of the node.
            expected_version: Expected Elasticsearch version.
            timeout: Maximum wait time in seconds.

        Returns:
            Dictionary with result.
        """
        self.logger.info(f"Waiting for node {node_name} with version {expected_version}")
        start_time = time.time()

        while time.time() - start_time < timeout:
            nodes = self.es.get_nodes_info()

            for node in nodes:
                if node.get("name") == node_name:
                    version = node.get("version")
                    if version == expected_version:
                        # Update node status
                        if self.state:
                            for ns in self.state.nodes:
                                if ns.node_name == node_name:
                                    ns.status = "completed"
                                    ns.new_version = version
                                    ns.completed_at = datetime.now().isoformat()

                        return {
                            "success": True,
                            "node": node_name,
                            "version": version,
                            "message": f"Node {node_name} rejoined with version {version}"
                        }
                    else:
                        self.logger.warning(
                            f"Node {node_name} found but version is {version}, expected {expected_version}"
                        )

            self.logger.info(f"Node {node_name} not found or version mismatch, waiting...")
            time.sleep(10)

        return {
            "success": False,
            "node": node_name,
            "message": f"Timeout waiting for node {node_name} after {timeout}s"
        }

    def get_current_status(self) -> Dict[str, Any]:
        """Get current upgrade status."""
        if not self.state:
            return {"status": "not_initialized"}

        return {
            "upgrade_id": self.state.upgrade_id,
            "current_phase": self.state.current_phase.value,
            "target_version": self.state.target_version,
            "started_at": self.state.started_at,
            "rollback_available": self.state.rollback_available,
            "steps": [
                {
                    "phase": s.phase.value,
                    "status": s.status,
                    "error": s.error
                }
                for s in self.state.steps
            ],
            "nodes": [
                {
                    "name": n.node_name,
                    "old_version": n.old_version,
                    "new_version": n.new_version,
                    "status": n.status
                }
                for n in self.state.nodes
            ]
        }

    def mark_phase_complete(self, phase: UpgradePhase) -> bool:
        """Manually mark a phase as complete."""
        if not self.state:
            return False

        step = next((s for s in self.state.steps if s.phase == phase), None)
        if step:
            step.status = "completed"
            step.completed_at = datetime.now().isoformat()
            return True
        return False

    def mark_node_upgraded(self, node_name: str, new_version: str) -> bool:
        """Manually mark a node as upgraded."""
        if not self.state:
            return False

        for node in self.state.nodes:
            if node.node_name == node_name:
                node.status = "completed"
                node.new_version = new_version
                node.completed_at = datetime.now().isoformat()
                return True
        return False

    def can_rollback(self) -> bool:
        """Check if rollback is still possible."""
        if not self.state:
            return False

        # Rollback is not possible after nodes have been upgraded
        upgraded_nodes = [n for n in self.state.nodes if n.status == "completed"]
        return len(upgraded_nodes) == 0 and self.state.rollback_available

    def get_rollback_instructions(self) -> List[str]:
        """Get rollback instructions."""
        instructions = [
            "ROLLBACK PROCEDURE",
            "=" * 50,
            "",
            "If upgrade fails and rollback is needed:",
            "",
            "1. Stop Elasticsearch on all nodes",
            "2. Restore previous Elasticsearch version on all nodes",
            "3. If data corruption occurred, restore from snapshot:",
        ]

        if self.snapshot_manager:
            repos = self.snapshot_manager.list_repositories()
            if repos:
                instructions.extend([
                    f"   - Repository: {repos[0]['name']}",
                    "   - Use the restore_snapshot command"
                ])

        instructions.extend([
            "",
            "4. Start Elasticsearch on all nodes",
            "5. Verify cluster health and data integrity",
            "",
            "NOTE: Rollback after successful node upgrades is not supported.",
            "You would need to restore from snapshot."
        ])

        return instructions

    def complete_upgrade(self) -> Dict[str, Any]:
        """Mark the upgrade as complete."""
        if not self.state:
            return {"error": "Upgrade not initialized"}

        # Verify all nodes are upgraded
        pending_nodes = [n for n in self.state.nodes if n.status != "completed"]
        if pending_nodes:
            return {
                "success": False,
                "message": f"{len(pending_nodes)} nodes still pending upgrade",
                "pending_nodes": [n.node_name for n in pending_nodes]
            }

        # Verify cluster health
        health = self.es.get_cluster_health()
        if health.get("status") != "green":
            return {
                "success": False,
                "message": f"Cluster health is {health.get('status')}, not GREEN"
            }

        self.state.current_phase = UpgradePhase.COMPLETED
        self.state.completed_at = datetime.now().isoformat()
        self.state.rollback_available = False

        return {
            "success": True,
            "message": "Upgrade completed successfully",
            "upgrade_id": self.state.upgrade_id,
            "duration": self._calculate_duration()
        }

    def _calculate_duration(self) -> str:
        """Calculate upgrade duration."""
        if not self.state or not self.state.completed_at:
            return "unknown"

        start = datetime.fromisoformat(self.state.started_at)
        end = datetime.fromisoformat(self.state.completed_at)
        duration = end - start

        hours, remainder = divmod(int(duration.total_seconds()), 3600)
        minutes, seconds = divmod(remainder, 60)

        if hours > 0:
            return f"{hours}h {minutes}m {seconds}s"
        elif minutes > 0:
            return f"{minutes}m {seconds}s"
        return f"{seconds}s"
