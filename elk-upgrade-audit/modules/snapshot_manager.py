"""
Snapshot Manager Module for ELK Upgrade Audit Tool
===================================================
Manages snapshot operations for backup and recovery during upgrades.
"""

import logging
import time
from typing import Dict, Any, List, Optional
from datetime import datetime
from dataclasses import dataclass
from enum import Enum


class SnapshotState(Enum):
    """Snapshot states."""
    IN_PROGRESS = "IN_PROGRESS"
    SUCCESS = "SUCCESS"
    FAILED = "FAILED"
    PARTIAL = "PARTIAL"
    UNKNOWN = "UNKNOWN"


@dataclass
class SnapshotInfo:
    """Information about a snapshot."""
    name: str
    repository: str
    state: SnapshotState
    start_time: str
    end_time: str
    duration_seconds: int
    indices: List[str]
    total_shards: int
    successful_shards: int
    failed_shards: int
    failures: List[str]


class SnapshotManager:
    """
    Manages Elasticsearch snapshot operations for upgrade backup and recovery.
    """

    def __init__(self, es_client, config):
        """
        Initialize the snapshot manager.

        Args:
            es_client: ElasticsearchClient instance
            config: ConfigManager instance
        """
        self.es = es_client
        self.config = config
        self.logger = logging.getLogger(__name__)

    def list_repositories(self) -> List[Dict[str, Any]]:
        """
        List all configured snapshot repositories.

        Returns:
            List of repository information dictionaries.
        """
        try:
            repos = self.es.client.snapshot.get_repository()
            result = []

            for name, settings in repos.items():
                result.append({
                    "name": name,
                    "type": settings.get("type"),
                    "settings": settings.get("settings", {})
                })

            return result
        except Exception as e:
            self.logger.error(f"Failed to list repositories: {e}")
            return []

    def verify_repository(self, repository: str) -> Dict[str, Any]:
        """
        Verify a snapshot repository is working.

        Args:
            repository: Name of the repository to verify.

        Returns:
            Dictionary with verification results.
        """
        try:
            result = self.es.client.snapshot.verify_repository(repository=repository)
            return {
                "repository": repository,
                "verified": True,
                "nodes": result.get("nodes", {})
            }
        except Exception as e:
            self.logger.error(f"Repository verification failed: {e}")
            return {
                "repository": repository,
                "verified": False,
                "error": str(e)
            }

    def create_repository(self, name: str, repo_type: str, settings: Dict[str, Any]) -> bool:
        """
        Create a new snapshot repository.

        Args:
            name: Repository name.
            repo_type: Repository type (fs, s3, gcs, azure).
            settings: Repository settings.

        Returns:
            True if successful, False otherwise.
        """
        try:
            self.es.client.snapshot.create_repository(
                repository=name,
                body={
                    "type": repo_type,
                    "settings": settings
                }
            )
            self.logger.info(f"Created snapshot repository: {name}")
            return True
        except Exception as e:
            self.logger.error(f"Failed to create repository: {e}")
            return False

    def list_snapshots(self, repository: str) -> List[SnapshotInfo]:
        """
        List all snapshots in a repository.

        Args:
            repository: Repository name.

        Returns:
            List of SnapshotInfo objects.
        """
        try:
            response = self.es.client.snapshot.get(repository=repository, snapshot="_all")
            snapshots = []

            for snap in response.get("snapshots", []):
                state = SnapshotState[snap.get("state", "UNKNOWN")]

                start_time = snap.get("start_time", "")
                end_time = snap.get("end_time", "")

                # Calculate duration
                start_millis = snap.get("start_time_in_millis", 0)
                end_millis = snap.get("end_time_in_millis", 0)
                duration = (end_millis - start_millis) // 1000 if end_millis > start_millis else 0

                snapshots.append(SnapshotInfo(
                    name=snap.get("snapshot"),
                    repository=repository,
                    state=state,
                    start_time=start_time,
                    end_time=end_time,
                    duration_seconds=duration,
                    indices=snap.get("indices", []),
                    total_shards=snap.get("shards", {}).get("total", 0),
                    successful_shards=snap.get("shards", {}).get("successful", 0),
                    failed_shards=snap.get("shards", {}).get("failed", 0),
                    failures=[f.get("reason") for f in snap.get("failures", [])]
                ))

            return sorted(snapshots, key=lambda x: x.start_time, reverse=True)

        except Exception as e:
            self.logger.error(f"Failed to list snapshots: {e}")
            return []

    def get_snapshot(self, repository: str, snapshot: str) -> Optional[SnapshotInfo]:
        """
        Get information about a specific snapshot.

        Args:
            repository: Repository name.
            snapshot: Snapshot name.

        Returns:
            SnapshotInfo or None if not found.
        """
        try:
            response = self.es.client.snapshot.get(repository=repository, snapshot=snapshot)
            snap = response.get("snapshots", [{}])[0]

            if not snap:
                return None

            state = SnapshotState[snap.get("state", "UNKNOWN")]
            start_millis = snap.get("start_time_in_millis", 0)
            end_millis = snap.get("end_time_in_millis", 0)
            duration = (end_millis - start_millis) // 1000 if end_millis > start_millis else 0

            return SnapshotInfo(
                name=snap.get("snapshot"),
                repository=repository,
                state=state,
                start_time=snap.get("start_time", ""),
                end_time=snap.get("end_time", ""),
                duration_seconds=duration,
                indices=snap.get("indices", []),
                total_shards=snap.get("shards", {}).get("total", 0),
                successful_shards=snap.get("shards", {}).get("successful", 0),
                failed_shards=snap.get("shards", {}).get("failed", 0),
                failures=[f.get("reason") for f in snap.get("failures", [])]
            )

        except Exception as e:
            self.logger.error(f"Failed to get snapshot: {e}")
            return None

    def create_pre_upgrade_snapshot(self, indices: Optional[List[str]] = None,
                                    wait_for_completion: bool = True) -> Dict[str, Any]:
        """
        Create a pre-upgrade snapshot.

        Args:
            indices: List of indices to snapshot (None for all).
            wait_for_completion: Whether to wait for completion.

        Returns:
            Dictionary with snapshot result.
        """
        repository = self.config.snapshot.repository
        name_pattern = self.config.snapshot.name_pattern
        snapshot_name = name_pattern.format(date=datetime.now().strftime("%Y%m%d-%H%M%S"))

        self.logger.info(f"Creating pre-upgrade snapshot: {snapshot_name}")

        try:
            body = {
                "ignore_unavailable": True,
                "include_global_state": True,
                "metadata": {
                    "taken_by": "elk-upgrade-audit",
                    "taken_because": "pre-upgrade-backup",
                    "timestamp": datetime.now().isoformat()
                }
            }

            if indices:
                body["indices"] = ",".join(indices)

            response = self.es.client.snapshot.create(
                repository=repository,
                snapshot=snapshot_name,
                body=body,
                wait_for_completion=wait_for_completion
            )

            if wait_for_completion:
                snapshot_info = response.get("snapshot", {})
                state = snapshot_info.get("state", "UNKNOWN")

                return {
                    "success": state == "SUCCESS",
                    "snapshot_name": snapshot_name,
                    "repository": repository,
                    "state": state,
                    "indices": snapshot_info.get("indices", []),
                    "shards": snapshot_info.get("shards", {}),
                    "duration_in_millis": snapshot_info.get("duration_in_millis", 0)
                }
            else:
                return {
                    "success": True,
                    "snapshot_name": snapshot_name,
                    "repository": repository,
                    "state": "IN_PROGRESS",
                    "message": "Snapshot started in background"
                }

        except Exception as e:
            self.logger.error(f"Failed to create snapshot: {e}")
            return {
                "success": False,
                "snapshot_name": snapshot_name,
                "repository": repository,
                "error": str(e)
            }

    def monitor_snapshot_progress(self, repository: str, snapshot: str,
                                  interval: int = 10) -> Dict[str, Any]:
        """
        Monitor snapshot progress until completion.

        Args:
            repository: Repository name.
            snapshot: Snapshot name.
            interval: Polling interval in seconds.

        Returns:
            Final snapshot status.
        """
        self.logger.info(f"Monitoring snapshot progress: {snapshot}")

        while True:
            try:
                status = self.es.client.snapshot.status(
                    repository=repository,
                    snapshot=snapshot
                )

                snapshots = status.get("snapshots", [])
                if not snapshots:
                    return {"error": "Snapshot not found"}

                snap_status = snapshots[0]
                state = snap_status.get("state", "UNKNOWN")

                # Calculate progress
                stats = snap_status.get("stats", {})
                total_size = stats.get("total", {}).get("size_in_bytes", 0)
                processed_size = stats.get("processed", {}).get("size_in_bytes", 0)
                progress = (processed_size / total_size * 100) if total_size > 0 else 0

                shards = snap_status.get("shards_stats", {})

                self.logger.info(
                    f"Snapshot progress: {progress:.1f}% - "
                    f"Shards: {shards.get('done', 0)}/{shards.get('total', 0)}"
                )

                if state in ["SUCCESS", "FAILED", "PARTIAL"]:
                    return {
                        "state": state,
                        "progress": 100 if state == "SUCCESS" else progress,
                        "stats": stats,
                        "shards": shards
                    }

                time.sleep(interval)

            except Exception as e:
                self.logger.error(f"Error monitoring snapshot: {e}")
                return {"error": str(e)}

    def delete_snapshot(self, repository: str, snapshot: str) -> bool:
        """
        Delete a snapshot.

        Args:
            repository: Repository name.
            snapshot: Snapshot name.

        Returns:
            True if successful, False otherwise.
        """
        try:
            self.es.client.snapshot.delete(repository=repository, snapshot=snapshot)
            self.logger.info(f"Deleted snapshot: {snapshot}")
            return True
        except Exception as e:
            self.logger.error(f"Failed to delete snapshot: {e}")
            return False

    def restore_snapshot(self, repository: str, snapshot: str,
                        indices: Optional[List[str]] = None,
                        rename_pattern: Optional[str] = None,
                        rename_replacement: Optional[str] = None) -> Dict[str, Any]:
        """
        Restore a snapshot.

        Args:
            repository: Repository name.
            snapshot: Snapshot name.
            indices: List of indices to restore (None for all).
            rename_pattern: Pattern for renaming indices.
            rename_replacement: Replacement for renaming indices.

        Returns:
            Dictionary with restore result.
        """
        self.logger.info(f"Restoring snapshot: {snapshot}")

        try:
            body = {
                "ignore_unavailable": True,
                "include_global_state": False,
                "include_aliases": True
            }

            if indices:
                body["indices"] = ",".join(indices)

            if rename_pattern and rename_replacement:
                body["rename_pattern"] = rename_pattern
                body["rename_replacement"] = rename_replacement

            response = self.es.client.snapshot.restore(
                repository=repository,
                snapshot=snapshot,
                body=body,
                wait_for_completion=True
            )

            return {
                "success": True,
                "snapshot": snapshot,
                "restored_indices": response.get("snapshot", {}).get("indices", []),
                "shards": response.get("snapshot", {}).get("shards", {})
            }

        except Exception as e:
            self.logger.error(f"Failed to restore snapshot: {e}")
            return {
                "success": False,
                "snapshot": snapshot,
                "error": str(e)
            }

    def get_snapshot_policy(self, policy_id: str) -> Optional[Dict[str, Any]]:
        """
        Get SLM policy information.

        Args:
            policy_id: Policy ID.

        Returns:
            Policy information or None.
        """
        try:
            policies = self.es.client.slm.get_lifecycle(policy_id=policy_id)
            return policies.get(policy_id)
        except Exception as e:
            self.logger.debug(f"Failed to get SLM policy: {e}")
            return None

    def list_snapshot_policies(self) -> List[Dict[str, Any]]:
        """
        List all SLM policies.

        Returns:
            List of policy information dictionaries.
        """
        try:
            policies = self.es.client.slm.get_lifecycle()
            result = []

            for policy_id, policy in policies.items():
                result.append({
                    "id": policy_id,
                    "name": policy.get("policy", {}).get("name"),
                    "schedule": policy.get("policy", {}).get("schedule"),
                    "repository": policy.get("policy", {}).get("repository"),
                    "next_execution": policy.get("next_execution"),
                    "last_success": policy.get("last_success", {}).get("time"),
                    "last_failure": policy.get("last_failure", {}).get("time")
                })

            return result
        except Exception as e:
            self.logger.debug(f"Failed to list SLM policies: {e}")
            return []

    def check_backup_readiness(self) -> Dict[str, Any]:
        """
        Check if the cluster is ready for backup before upgrade.

        Returns:
            Dictionary with readiness status and recommendations.
        """
        issues = []
        warnings = []
        recommendations = []

        # Check repositories
        repos = self.list_repositories()
        if not repos:
            issues.append("No snapshot repository configured")
            recommendations.append("Configure a snapshot repository before upgrade")
        else:
            # Verify default repository
            default_repo = self.config.snapshot.repository
            if default_repo not in [r["name"] for r in repos]:
                warnings.append(f"Default repository '{default_repo}' not found")
                recommendations.append(f"Create repository '{default_repo}' or update configuration")
            else:
                # Verify repository is working
                verification = self.verify_repository(default_repo)
                if not verification.get("verified"):
                    issues.append(f"Repository '{default_repo}' verification failed")
                    recommendations.append("Fix repository connectivity issues")

        # Check for recent successful snapshot
        if repos:
            for repo in repos:
                snapshots = self.list_snapshots(repo["name"])
                successful = [s for s in snapshots if s.state == SnapshotState.SUCCESS]

                if successful:
                    latest = successful[0]
                    # Check if latest snapshot is recent (within 24 hours)
                    try:
                        snap_time = datetime.fromisoformat(latest.start_time.replace("Z", "+00:00"))
                        age_hours = (datetime.now(snap_time.tzinfo) - snap_time).total_seconds() / 3600

                        if age_hours > 24:
                            warnings.append(f"Latest successful snapshot is {age_hours:.0f} hours old")
                            recommendations.append("Create a fresh snapshot before upgrade")
                    except Exception:
                        pass
                else:
                    warnings.append(f"No successful snapshots in repository '{repo['name']}'")
                    recommendations.append("Create at least one successful snapshot before upgrade")

        # Check cluster health for backup
        health = self.es.get_cluster_health()
        if health.get("status") == "red":
            issues.append("Cluster is RED - snapshot may not capture all data")
            recommendations.append("Resolve cluster health issues before backup")

        return {
            "ready": len(issues) == 0,
            "issues": issues,
            "warnings": warnings,
            "recommendations": recommendations,
            "repositories": repos
        }

    def estimate_snapshot_size(self) -> Dict[str, Any]:
        """
        Estimate the size of a full cluster snapshot.

        Returns:
            Dictionary with size estimates.
        """
        try:
            indices = self.es.get_indices_info()
            total_size = sum(i.get("store_size", 0) for i in indices if "error" not in i)
            primary_size = sum(i.get("pri_store_size", 0) for i in indices if "error" not in i)

            return {
                "total_size_bytes": total_size,
                "total_size_gb": round(total_size / (1024**3), 2),
                "primary_size_bytes": primary_size,
                "primary_size_gb": round(primary_size / (1024**3), 2),
                "index_count": len(indices),
                "estimated_snapshot_size_gb": round(primary_size / (1024**3), 2)  # Snapshots store primary data
            }
        except Exception as e:
            self.logger.error(f"Failed to estimate snapshot size: {e}")
            return {"error": str(e)}
