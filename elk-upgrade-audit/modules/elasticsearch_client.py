"""
Elasticsearch Client for ELK Upgrade Audit Tool
================================================
Provides a wrapper around the Elasticsearch Python client with additional
functionality for upgrade auditing.
"""

import logging
import urllib3
from typing import Dict, Any, Optional, List
from datetime import datetime

# Disable SSL warnings for self-signed certificates
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

try:
    from elasticsearch import Elasticsearch, exceptions as es_exceptions
    HAS_ELASTICSEARCH = True
except ImportError:
    HAS_ELASTICSEARCH = False
    Elasticsearch = None
    es_exceptions = None


class ElasticsearchClient:
    """
    Wrapper around the Elasticsearch client with upgrade-specific functionality.
    """

    def __init__(self, config):
        """
        Initialize the Elasticsearch client.

        Args:
            config: ElasticsearchConfig object with connection settings.
        """
        self.config = config
        self.client: Optional[Elasticsearch] = None
        self.logger = logging.getLogger(__name__)
        self.connected = False
        self.cluster_info: Dict[str, Any] = {}

    def connect(self) -> bool:
        """
        Establish connection to the Elasticsearch cluster.

        Returns:
            True if connection successful, False otherwise.
        """
        if not HAS_ELASTICSEARCH:
            self.logger.error("elasticsearch-py package not installed. Run: pip install elasticsearch")
            return False

        try:
            client_kwargs = {
                'hosts': self.config.hosts,
                'request_timeout': self.config.timeout,
                'max_retries': self.config.max_retries,
                'retry_on_timeout': True
            }

            # Add authentication if provided
            if self.config.username and self.config.password:
                client_kwargs['basic_auth'] = (self.config.username, self.config.password)

            # Add SSL settings
            if not self.config.verify_certs:
                client_kwargs['verify_certs'] = False
                client_kwargs['ssl_show_warn'] = False
            elif self.config.ca_certs:
                client_kwargs['ca_certs'] = self.config.ca_certs

            self.client = Elasticsearch(**client_kwargs)

            # Test connection
            self.cluster_info = self.client.info()
            self.connected = True
            self.logger.info(f"Connected to Elasticsearch cluster: {self.cluster_info.get('cluster_name')}")
            self.logger.info(f"Elasticsearch version: {self.cluster_info.get('version', {}).get('number')}")

            return True

        except Exception as e:
            self.logger.error(f"Failed to connect to Elasticsearch: {e}")
            self.connected = False
            return False

    def disconnect(self):
        """Close the Elasticsearch connection."""
        if self.client:
            self.client.close()
            self.connected = False
            self.logger.info("Disconnected from Elasticsearch")

    def get_cluster_health(self) -> Dict[str, Any]:
        """
        Get detailed cluster health information.

        Returns:
            Dictionary containing cluster health data.
        """
        if not self.connected:
            return {"error": "Not connected to Elasticsearch"}

        try:
            health = self.client.cluster.health()
            return {
                "cluster_name": health.get("cluster_name"),
                "status": health.get("status"),
                "timed_out": health.get("timed_out"),
                "number_of_nodes": health.get("number_of_nodes"),
                "number_of_data_nodes": health.get("number_of_data_nodes"),
                "active_primary_shards": health.get("active_primary_shards"),
                "active_shards": health.get("active_shards"),
                "relocating_shards": health.get("relocating_shards"),
                "initializing_shards": health.get("initializing_shards"),
                "unassigned_shards": health.get("unassigned_shards"),
                "delayed_unassigned_shards": health.get("delayed_unassigned_shards"),
                "number_of_pending_tasks": health.get("number_of_pending_tasks"),
                "number_of_in_flight_fetch": health.get("number_of_in_flight_fetch"),
                "task_max_waiting_in_queue_millis": health.get("task_max_waiting_in_queue_millis"),
                "active_shards_percent_as_number": health.get("active_shards_percent_as_number"),
                "timestamp": datetime.now().isoformat()
            }
        except Exception as e:
            self.logger.error(f"Error getting cluster health: {e}")
            return {"error": str(e)}

    def get_nodes_info(self) -> List[Dict[str, Any]]:
        """
        Get detailed information about all nodes in the cluster.

        Returns:
            List of dictionaries containing node information.
        """
        if not self.connected:
            return [{"error": "Not connected to Elasticsearch"}]

        try:
            nodes = self.client.nodes.info()
            nodes_stats = self.client.nodes.stats()

            result = []
            for node_id, node_info in nodes.get("nodes", {}).items():
                node_stats = nodes_stats.get("nodes", {}).get(node_id, {})

                result.append({
                    "node_id": node_id,
                    "name": node_info.get("name"),
                    "version": node_info.get("version"),
                    "build_hash": node_info.get("build_hash"),
                    "roles": node_info.get("roles", []),
                    "ip": node_info.get("ip"),
                    "host": node_info.get("host"),
                    "transport_address": node_info.get("transport_address"),
                    "os": {
                        "name": node_info.get("os", {}).get("name"),
                        "version": node_info.get("os", {}).get("version"),
                        "arch": node_info.get("os", {}).get("arch"),
                        "available_processors": node_info.get("os", {}).get("available_processors"),
                        "allocated_processors": node_info.get("os", {}).get("allocated_processors")
                    },
                    "jvm": {
                        "version": node_info.get("jvm", {}).get("version"),
                        "vm_name": node_info.get("jvm", {}).get("vm_name"),
                        "heap_max": node_info.get("jvm", {}).get("mem", {}).get("heap_max"),
                        "heap_init": node_info.get("jvm", {}).get("mem", {}).get("heap_init")
                    },
                    "stats": {
                        "heap_used_percent": node_stats.get("jvm", {}).get("mem", {}).get("heap_used_percent"),
                        "heap_used": node_stats.get("jvm", {}).get("mem", {}).get("heap_used_in_bytes"),
                        "heap_max": node_stats.get("jvm", {}).get("mem", {}).get("heap_max_in_bytes"),
                        "disk_total": node_stats.get("fs", {}).get("total", {}).get("total_in_bytes"),
                        "disk_available": node_stats.get("fs", {}).get("total", {}).get("available_in_bytes"),
                        "cpu_percent": node_stats.get("os", {}).get("cpu", {}).get("percent")
                    },
                    "plugins": [p.get("name") for p in node_info.get("plugins", [])]
                })

            return result

        except Exception as e:
            self.logger.error(f"Error getting nodes info: {e}")
            return [{"error": str(e)}]

    def get_indices_info(self) -> List[Dict[str, Any]]:
        """
        Get information about all indices.

        Returns:
            List of dictionaries containing index information.
        """
        if not self.connected:
            return [{"error": "Not connected to Elasticsearch"}]

        try:
            indices = self.client.cat.indices(format="json", bytes="b")
            result = []

            for index in indices:
                result.append({
                    "index": index.get("index"),
                    "health": index.get("health"),
                    "status": index.get("status"),
                    "uuid": index.get("uuid"),
                    "pri": int(index.get("pri", 0)),
                    "rep": int(index.get("rep", 0)),
                    "docs_count": int(index.get("docs.count", 0) or 0),
                    "docs_deleted": int(index.get("docs.deleted", 0) or 0),
                    "store_size": int(index.get("store.size", 0) or 0),
                    "pri_store_size": int(index.get("pri.store.size", 0) or 0)
                })

            return sorted(result, key=lambda x: x.get("store_size", 0), reverse=True)

        except Exception as e:
            self.logger.error(f"Error getting indices info: {e}")
            return [{"error": str(e)}]

    def get_shards_info(self) -> List[Dict[str, Any]]:
        """
        Get detailed shard allocation information.

        Returns:
            List of dictionaries containing shard information.
        """
        if not self.connected:
            return [{"error": "Not connected to Elasticsearch"}]

        try:
            shards = self.client.cat.shards(format="json", bytes="b")
            result = []

            for shard in shards:
                result.append({
                    "index": shard.get("index"),
                    "shard": shard.get("shard"),
                    "prirep": shard.get("prirep"),
                    "state": shard.get("state"),
                    "docs": int(shard.get("docs", 0) or 0),
                    "store": int(shard.get("store", 0) or 0),
                    "ip": shard.get("ip"),
                    "node": shard.get("node"),
                    "unassigned_reason": shard.get("unassigned.reason")
                })

            return result

        except Exception as e:
            self.logger.error(f"Error getting shards info: {e}")
            return [{"error": str(e)}]

    def get_deprecation_info(self) -> Dict[str, Any]:
        """
        Get deprecation warnings for the cluster.

        Returns:
            Dictionary containing deprecation information.
        """
        if not self.connected:
            return {"error": "Not connected to Elasticsearch"}

        try:
            # Try the migration deprecation API (available in ES 7.x+)
            deprecations = self.client.migration.deprecations()
            return {
                "cluster_settings": deprecations.get("cluster_settings", []),
                "node_settings": deprecations.get("node_settings", []),
                "index_settings": deprecations.get("index_settings", {}),
                "ml_settings": deprecations.get("ml_settings", []),
                "timestamp": datetime.now().isoformat()
            }
        except AttributeError:
            # migration.deprecations() not available in older versions
            self.logger.warning("Deprecation API not available in this Elasticsearch version")
            return {"warning": "Deprecation API not available", "cluster_settings": [], "index_settings": {}}
        except Exception as e:
            self.logger.error(f"Error getting deprecation info: {e}")
            return {"error": str(e)}

    def get_cluster_settings(self) -> Dict[str, Any]:
        """
        Get current cluster settings.

        Returns:
            Dictionary containing cluster settings.
        """
        if not self.connected:
            return {"error": "Not connected to Elasticsearch"}

        try:
            settings = self.client.cluster.get_settings(include_defaults=True, flat_settings=True)
            return {
                "persistent": settings.get("persistent", {}),
                "transient": settings.get("transient", {}),
                "defaults": settings.get("defaults", {})
            }
        except Exception as e:
            self.logger.error(f"Error getting cluster settings: {e}")
            return {"error": str(e)}

    def get_index_templates(self) -> Dict[str, Any]:
        """
        Get all index templates.

        Returns:
            Dictionary containing template information.
        """
        if not self.connected:
            return {"error": "Not connected to Elasticsearch"}

        try:
            # Get legacy templates
            legacy_templates = self.client.indices.get_template()

            # Try to get component and composable templates (ES 7.8+)
            try:
                component_templates = self.client.cluster.get_component_template()
                composable_templates = self.client.indices.get_index_template()
            except Exception:
                component_templates = {}
                composable_templates = {}

            return {
                "legacy_templates": legacy_templates,
                "component_templates": component_templates,
                "composable_templates": composable_templates
            }
        except Exception as e:
            self.logger.error(f"Error getting index templates: {e}")
            return {"error": str(e)}

    def get_snapshot_repositories(self) -> Dict[str, Any]:
        """
        Get snapshot repository information.

        Returns:
            Dictionary containing repository information.
        """
        if not self.connected:
            return {"error": "Not connected to Elasticsearch"}

        try:
            repos = self.client.snapshot.get_repository()
            return repos
        except Exception as e:
            self.logger.error(f"Error getting snapshot repositories: {e}")
            return {"error": str(e)}

    def get_snapshots(self, repository: str) -> List[Dict[str, Any]]:
        """
        Get all snapshots in a repository.

        Args:
            repository: Name of the snapshot repository.

        Returns:
            List of snapshot information.
        """
        if not self.connected:
            return [{"error": "Not connected to Elasticsearch"}]

        try:
            snapshots = self.client.snapshot.get(repository=repository, snapshot="_all")
            return snapshots.get("snapshots", [])
        except Exception as e:
            self.logger.error(f"Error getting snapshots: {e}")
            return [{"error": str(e)}]

    def get_pending_tasks(self) -> List[Dict[str, Any]]:
        """
        Get pending cluster tasks.

        Returns:
            List of pending tasks.
        """
        if not self.connected:
            return [{"error": "Not connected to Elasticsearch"}]

        try:
            tasks = self.client.cluster.pending_tasks()
            return tasks.get("tasks", [])
        except Exception as e:
            self.logger.error(f"Error getting pending tasks: {e}")
            return [{"error": str(e)}]

    def get_allocation_explain(self) -> Dict[str, Any]:
        """
        Get explanation for shard allocation issues.

        Returns:
            Dictionary with allocation explanation.
        """
        if not self.connected:
            return {"error": "Not connected to Elasticsearch"}

        try:
            explain = self.client.cluster.allocation_explain()
            return explain
        except Exception as e:
            # No unassigned shards is a good thing
            if "unable to find any unassigned shards" in str(e).lower():
                return {"status": "ok", "message": "No unassigned shards"}
            self.logger.error(f"Error getting allocation explanation: {e}")
            return {"error": str(e)}

    def get_version(self) -> str:
        """
        Get the Elasticsearch version.

        Returns:
            Version string.
        """
        if not self.connected:
            return "unknown"

        return self.cluster_info.get("version", {}).get("number", "unknown")

    def get_cluster_uuid(self) -> str:
        """
        Get the cluster UUID.

        Returns:
            Cluster UUID string.
        """
        if not self.connected:
            return "unknown"

        return self.cluster_info.get("cluster_uuid", "unknown")

    def disable_shard_allocation(self) -> bool:
        """
        Disable shard allocation (for rolling upgrades).

        Returns:
            True if successful, False otherwise.
        """
        if not self.connected:
            return False

        try:
            self.client.cluster.put_settings(
                body={
                    "persistent": {
                        "cluster.routing.allocation.enable": "primaries"
                    }
                }
            )
            self.logger.info("Shard allocation disabled (primaries only)")
            return True
        except Exception as e:
            self.logger.error(f"Error disabling shard allocation: {e}")
            return False

    def enable_shard_allocation(self) -> bool:
        """
        Re-enable shard allocation.

        Returns:
            True if successful, False otherwise.
        """
        if not self.connected:
            return False

        try:
            self.client.cluster.put_settings(
                body={
                    "persistent": {
                        "cluster.routing.allocation.enable": "all"
                    }
                }
            )
            self.logger.info("Shard allocation re-enabled")
            return True
        except Exception as e:
            self.logger.error(f"Error enabling shard allocation: {e}")
            return False

    def flush_synced(self) -> bool:
        """
        Perform a synced flush on all indices.

        Returns:
            True if successful, False otherwise.
        """
        if not self.connected:
            return False

        try:
            # synced_flush is deprecated in 7.6+, use regular flush
            self.client.indices.flush(wait_if_ongoing=True)
            self.logger.info("Flush completed on all indices")
            return True
        except Exception as e:
            self.logger.error(f"Error performing flush: {e}")
            return False

    def execute_query(self, method: str, endpoint: str, body: Optional[Dict] = None) -> Dict[str, Any]:
        """
        Execute a raw Elasticsearch query.

        Args:
            method: HTTP method (GET, POST, PUT, DELETE)
            endpoint: API endpoint
            body: Optional request body

        Returns:
            Response dictionary.
        """
        if not self.connected:
            return {"error": "Not connected to Elasticsearch"}

        try:
            response = self.client.perform_request(method, endpoint, body=body)
            return response
        except Exception as e:
            self.logger.error(f"Error executing query: {e}")
            return {"error": str(e)}
