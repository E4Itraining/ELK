"""
Elasticsearch Client Module
===========================

Provides a specialized Elasticsearch client for AI monitoring operations
with support for bulk indexing, template management, and ILM policies.
"""

import json
import logging
from datetime import datetime, timezone
from typing import Dict, List, Optional, Any
from pathlib import Path

from elasticsearch import Elasticsearch, helpers
from elasticsearch.exceptions import (
    ConnectionError,
    TransportError,
    NotFoundError,
    RequestError,
)

from .config import Config, ElasticsearchConfig

logger = logging.getLogger(__name__)


class AIMonitoringClient:
    """
    Elasticsearch client specialized for AI monitoring operations.

    Provides methods for:
    - Index and template management
    - Bulk document indexing
    - Metrics aggregation queries
    - ILM policy management
    """

    def __init__(self, config: Config):
        """
        Initialize the AI Monitoring Elasticsearch client.

        Args:
            config: Configuration object containing ES connection settings
        """
        self.config = config
        self.es_config = config.elasticsearch
        self._client: Optional[Elasticsearch] = None
        self._connected = False

    @property
    def client(self) -> Elasticsearch:
        """Get or create Elasticsearch client connection."""
        if self._client is None:
            self._connect()
        return self._client

    def _connect(self) -> None:
        """Establish connection to Elasticsearch."""
        try:
            connection_params = {
                "hosts": self.es_config.hosts,
                "basic_auth": (self.es_config.username, self.es_config.password),
                "verify_certs": self.es_config.verify_certs,
                "ssl_show_warn": self.es_config.ssl_show_warn,
                "request_timeout": self.es_config.timeout,
                "max_retries": self.es_config.max_retries,
                "retry_on_timeout": True,
            }

            if self.es_config.ca_certs:
                connection_params["ca_certs"] = self.es_config.ca_certs

            self._client = Elasticsearch(**connection_params)

            # Verify connection
            info = self._client.info()
            logger.info(
                f"Connected to Elasticsearch cluster: {info['cluster_name']} "
                f"(version {info['version']['number']})"
            )
            self._connected = True

        except ConnectionError as e:
            logger.error(f"Failed to connect to Elasticsearch: {e}")
            raise
        except Exception as e:
            logger.error(f"Unexpected error connecting to Elasticsearch: {e}")
            raise

    def is_connected(self) -> bool:
        """Check if connected to Elasticsearch."""
        if not self._connected or self._client is None:
            return False
        try:
            return self._client.ping()
        except Exception:
            return False

    def get_cluster_health(self) -> Dict[str, Any]:
        """Get cluster health status."""
        return self.client.cluster.health()

    def get_cluster_stats(self) -> Dict[str, Any]:
        """Get cluster statistics."""
        return self.client.cluster.stats()

    # ==========================================================================
    # Template Management
    # ==========================================================================

    def install_index_template(
        self,
        template_name: str,
        template_body: Dict[str, Any]
    ) -> bool:
        """
        Install an index template.

        Args:
            template_name: Name of the template
            template_body: Template definition

        Returns:
            True if successful
        """
        try:
            self.client.indices.put_index_template(
                name=template_name,
                body=template_body
            )
            logger.info(f"Installed index template: {template_name}")
            return True
        except RequestError as e:
            logger.error(f"Failed to install template {template_name}: {e}")
            raise

    def install_templates_from_directory(self, directory: str) -> Dict[str, bool]:
        """
        Install all templates from a directory.

        Args:
            directory: Path to directory containing template JSON files

        Returns:
            Dictionary mapping template names to installation status
        """
        results = {}
        template_dir = Path(directory)

        for template_file in template_dir.glob("*_template.json"):
            template_name = template_file.stem.replace("_template", "")

            try:
                with open(template_file, 'r') as f:
                    template_body = json.load(f)

                results[template_name] = self.install_index_template(
                    template_name, template_body
                )
            except Exception as e:
                logger.error(f"Failed to install template from {template_file}: {e}")
                results[template_name] = False

        return results

    def get_index_template(self, template_name: str) -> Optional[Dict[str, Any]]:
        """Get an index template by name."""
        try:
            return self.client.indices.get_index_template(name=template_name)
        except NotFoundError:
            return None

    def delete_index_template(self, template_name: str) -> bool:
        """Delete an index template."""
        try:
            self.client.indices.delete_index_template(name=template_name)
            logger.info(f"Deleted index template: {template_name}")
            return True
        except NotFoundError:
            logger.warning(f"Template not found: {template_name}")
            return False

    # ==========================================================================
    # ILM Policy Management
    # ==========================================================================

    def install_ilm_policy(self, policy_name: str, policy_body: Dict[str, Any]) -> bool:
        """
        Install an ILM policy.

        Args:
            policy_name: Name of the policy
            policy_body: Policy definition

        Returns:
            True if successful
        """
        try:
            self.client.ilm.put_lifecycle(name=policy_name, policy=policy_body)
            logger.info(f"Installed ILM policy: {policy_name}")
            return True
        except RequestError as e:
            logger.error(f"Failed to install ILM policy {policy_name}: {e}")
            raise

    def install_ilm_policies_from_file(self, filepath: str) -> Dict[str, bool]:
        """
        Install ILM policies from a JSON file.

        Args:
            filepath: Path to JSON file containing policy definitions

        Returns:
            Dictionary mapping policy names to installation status
        """
        results = {}

        try:
            with open(filepath, 'r') as f:
                policies = json.load(f)

            for policy_name, policy_data in policies.items():
                try:
                    results[policy_name] = self.install_ilm_policy(
                        policy_name,
                        policy_data.get('policy', policy_data)
                    )
                except Exception as e:
                    logger.error(f"Failed to install policy {policy_name}: {e}")
                    results[policy_name] = False

        except Exception as e:
            logger.error(f"Failed to load policies from {filepath}: {e}")
            raise

        return results

    def get_ilm_policy(self, policy_name: str) -> Optional[Dict[str, Any]]:
        """Get an ILM policy by name."""
        try:
            return self.client.ilm.get_lifecycle(name=policy_name)
        except NotFoundError:
            return None

    # ==========================================================================
    # Index Management
    # ==========================================================================

    def create_index(
        self,
        index_name: str,
        mappings: Optional[Dict[str, Any]] = None,
        settings: Optional[Dict[str, Any]] = None,
        aliases: Optional[Dict[str, Any]] = None
    ) -> bool:
        """
        Create an index.

        Args:
            index_name: Name of the index
            mappings: Index mappings
            settings: Index settings
            aliases: Index aliases

        Returns:
            True if successful
        """
        try:
            body = {}
            if mappings:
                body['mappings'] = mappings
            if settings:
                body['settings'] = settings
            if aliases:
                body['aliases'] = aliases

            self.client.indices.create(index=index_name, body=body if body else None)
            logger.info(f"Created index: {index_name}")
            return True
        except RequestError as e:
            if 'resource_already_exists_exception' in str(e):
                logger.warning(f"Index already exists: {index_name}")
                return True
            logger.error(f"Failed to create index {index_name}: {e}")
            raise

    def create_initial_indices(self) -> Dict[str, bool]:
        """
        Create initial indices for all metric types with write aliases.

        Returns:
            Dictionary mapping index names to creation status
        """
        results = {}

        indices = [
            ("ai-technical-metrics-000001", "ai-technical-metrics"),
            ("ai-cognitive-metrics-000001", "ai-cognitive-metrics"),
            ("ai-finops-metrics-000001", "ai-finops-metrics"),
            ("ai-devops-metrics-000001", "ai-devops-metrics"),
            ("ai-compliance-metrics-000001", "ai-compliance-metrics"),
        ]

        for index_name, alias_name in indices:
            try:
                # Check if alias already exists
                if self.client.indices.exists_alias(name=alias_name):
                    logger.info(f"Alias already exists: {alias_name}")
                    results[index_name] = True
                    continue

                results[index_name] = self.create_index(
                    index_name=index_name,
                    aliases={alias_name: {"is_write_index": True}}
                )
            except Exception as e:
                logger.error(f"Failed to create index {index_name}: {e}")
                results[index_name] = False

        return results

    def index_exists(self, index_name: str) -> bool:
        """Check if an index exists."""
        return self.client.indices.exists(index=index_name)

    def delete_index(self, index_name: str) -> bool:
        """Delete an index."""
        try:
            self.client.indices.delete(index=index_name)
            logger.info(f"Deleted index: {index_name}")
            return True
        except NotFoundError:
            logger.warning(f"Index not found: {index_name}")
            return False

    # ==========================================================================
    # Document Operations
    # ==========================================================================

    def index_document(
        self,
        index: str,
        document: Dict[str, Any],
        doc_id: Optional[str] = None,
        refresh: bool = False
    ) -> Dict[str, Any]:
        """
        Index a single document.

        Args:
            index: Target index name
            document: Document to index
            doc_id: Optional document ID
            refresh: Whether to refresh the index after indexing

        Returns:
            Indexing response
        """
        # Ensure timestamp
        if '@timestamp' not in document:
            document['@timestamp'] = datetime.now(timezone.utc).isoformat()

        params = {
            "index": index,
            "document": document,
            "refresh": "true" if refresh else "false",
        }

        if doc_id:
            params["id"] = doc_id

        return self.client.index(**params)

    def bulk_index(
        self,
        index: str,
        documents: List[Dict[str, Any]],
        refresh: bool = False
    ) -> Dict[str, Any]:
        """
        Bulk index multiple documents.

        Args:
            index: Target index name
            documents: List of documents to index
            refresh: Whether to refresh the index after indexing

        Returns:
            Bulk indexing statistics
        """
        if not documents:
            return {"indexed": 0, "errors": 0}

        # Prepare bulk actions
        actions = []
        for doc in documents:
            # Ensure timestamp
            if '@timestamp' not in doc:
                doc['@timestamp'] = datetime.now(timezone.utc).isoformat()

            action = {
                "_index": index,
                "_source": doc,
            }

            # Use request_id as document ID if available
            if 'request_id' in doc:
                action["_id"] = doc['request_id']

            actions.append(action)

        # Execute bulk operation
        try:
            success, errors = helpers.bulk(
                self.client,
                actions,
                chunk_size=500,
                request_timeout=120,
                refresh=refresh,
                raise_on_error=False,
                stats_only=False,
            )

            error_count = len(errors) if isinstance(errors, list) else errors

            logger.debug(f"Bulk indexed {success} documents with {error_count} errors")

            return {
                "indexed": success,
                "errors": error_count,
                "error_details": errors if isinstance(errors, list) else [],
            }

        except Exception as e:
            logger.error(f"Bulk indexing failed: {e}")
            raise

    # ==========================================================================
    # Query Operations
    # ==========================================================================

    def search(
        self,
        index: str,
        query: Dict[str, Any],
        size: int = 100,
        sort: Optional[List[Dict[str, Any]]] = None,
        aggs: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        Execute a search query.

        Args:
            index: Index pattern to search
            query: Elasticsearch query DSL
            size: Maximum number of hits to return
            sort: Sort specification
            aggs: Aggregations

        Returns:
            Search response
        """
        body = {"query": query, "size": size}

        if sort:
            body["sort"] = sort
        if aggs:
            body["aggs"] = aggs

        return self.client.search(index=index, body=body)

    def aggregate(
        self,
        index: str,
        aggs: Dict[str, Any],
        query: Optional[Dict[str, Any]] = None,
        size: int = 0
    ) -> Dict[str, Any]:
        """
        Execute an aggregation query.

        Args:
            index: Index pattern to aggregate
            aggs: Aggregations definition
            query: Optional filter query
            size: Number of hits (usually 0 for pure aggregations)

        Returns:
            Aggregation response
        """
        body = {"aggs": aggs, "size": size}

        if query:
            body["query"] = query

        return self.client.search(index=index, body=body)

    def get_metrics_summary(
        self,
        index_prefix: str,
        time_range: str = "24h",
        group_by: Optional[List[str]] = None
    ) -> Dict[str, Any]:
        """
        Get a summary of metrics for a given time range.

        Args:
            index_prefix: Index prefix to query
            time_range: Time range (e.g., "24h", "7d", "30d")
            group_by: Optional fields to group by

        Returns:
            Metrics summary
        """
        query = {
            "bool": {
                "filter": [
                    {"range": {"@timestamp": {"gte": f"now-{time_range}"}}}
                ]
            }
        }

        aggs = {
            "total_docs": {"value_count": {"field": "@timestamp"}},
            "over_time": {
                "date_histogram": {
                    "field": "@timestamp",
                    "fixed_interval": self._get_interval_for_range(time_range),
                }
            }
        }

        if group_by:
            for field in group_by:
                aggs[f"by_{field}"] = {
                    "terms": {"field": field, "size": 50}
                }

        return self.aggregate(
            index=f"{index_prefix}-*",
            aggs=aggs,
            query=query
        )

    def _get_interval_for_range(self, time_range: str) -> str:
        """Get appropriate histogram interval for time range."""
        if time_range.endswith('h'):
            hours = int(time_range[:-1])
            if hours <= 6:
                return "5m"
            elif hours <= 24:
                return "1h"
            else:
                return "6h"
        elif time_range.endswith('d'):
            days = int(time_range[:-1])
            if days <= 7:
                return "6h"
            elif days <= 30:
                return "1d"
            else:
                return "1w"
        return "1h"

    # ==========================================================================
    # Utility Methods
    # ==========================================================================

    def refresh_index(self, index: str) -> None:
        """Refresh an index."""
        self.client.indices.refresh(index=index)

    def get_index_stats(self, index: str) -> Dict[str, Any]:
        """Get statistics for an index."""
        return self.client.indices.stats(index=index)

    def count_documents(
        self,
        index: str,
        query: Optional[Dict[str, Any]] = None
    ) -> int:
        """Count documents in an index."""
        body = {"query": query} if query else None
        result = self.client.count(index=index, body=body)
        return result["count"]

    def close(self) -> None:
        """Close the Elasticsearch connection."""
        if self._client:
            self._client.close()
            self._client = None
            self._connected = False
            logger.info("Elasticsearch connection closed")
