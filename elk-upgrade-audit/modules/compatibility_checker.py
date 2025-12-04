"""
Compatibility Checker Module for ELK Upgrade Audit Tool
========================================================
Checks version compatibility and upgrade paths for Elasticsearch.
"""

import logging
import re
from typing import Dict, Any, List, Tuple, Optional
from dataclasses import dataclass
from enum import Enum


class UpgradeType(Enum):
    """Type of upgrade required."""
    MINOR = "minor"           # 8.10 -> 8.11
    MAJOR = "major"           # 7.x -> 8.x
    ROLLING = "rolling"       # Can be done with rolling restart
    FULL_RESTART = "full"     # Requires full cluster restart
    DOUBLE_MAJOR = "double_major"  # Double major upgrade (e.g., 7.x -> 9.x)
    REINDEX = "reindex"       # Requires reindexing
    NOT_SUPPORTED = "not_supported"  # Direct upgrade not supported


@dataclass
class Version:
    """Parsed semantic version."""
    major: int
    minor: int
    patch: int
    qualifier: str = ""

    @classmethod
    def parse(cls, version_str: str) -> 'Version':
        """Parse a version string into a Version object."""
        # Handle versions like "8.11.0", "7.17.0-SNAPSHOT", etc.
        match = re.match(r'^(\d+)\.(\d+)\.(\d+)(?:-(.+))?$', version_str)
        if not match:
            raise ValueError(f"Invalid version format: {version_str}")

        return cls(
            major=int(match.group(1)),
            minor=int(match.group(2)),
            patch=int(match.group(3)),
            qualifier=match.group(4) or ""
        )

    def __str__(self) -> str:
        base = f"{self.major}.{self.minor}.{self.patch}"
        return f"{base}-{self.qualifier}" if self.qualifier else base

    def __lt__(self, other: 'Version') -> bool:
        return (self.major, self.minor, self.patch) < (other.major, other.minor, other.patch)

    def __eq__(self, other: 'Version') -> bool:
        return (self.major, self.minor, self.patch) == (other.major, other.minor, other.patch)

    def __le__(self, other: 'Version') -> bool:
        return self < other or self == other


@dataclass
class CompatibilityResult:
    """Result of a compatibility check."""
    compatible: bool
    upgrade_type: UpgradeType
    upgrade_path: List[str]
    warnings: List[str]
    blockers: List[str]
    recommendations: List[str]
    breaking_changes: List[Dict[str, str]]


class CompatibilityChecker:
    """
    Checks version compatibility and determines upgrade paths.
    """

    # Supported upgrade paths
    SUPPORTED_UPGRADES = {
        # From version: [list of supported target versions]
        "6.8": ["7.17"],
        "7.0": ["7.17", "8.0"],
        "7.1": ["7.17", "8.0"],
        "7.17": ["8.0", "8.1", "8.2", "8.3", "8.4", "8.5", "8.6", "8.7", "8.8", "8.9", "8.10", "8.11", "8.12", "8.13", "8.14", "8.15", "8.16", "8.17", "8.18"],
        "8.0": ["8.1", "8.2", "8.3", "8.4", "8.5", "8.6", "8.7", "8.8", "8.9", "8.10", "8.11", "8.12", "8.13", "8.14", "8.15", "8.16", "8.17", "8.18"],
        # ES 8.x to 9.x upgrade paths - requires 8.18 minimum for direct upgrade to 9.x
        "8.18": ["9.0", "9.1"],
        "9.0": ["9.1"],
    }

    # Breaking changes database
    BREAKING_CHANGES = {
        "7_to_8": [
            {
                "category": "Security",
                "change": "Security is enabled by default",
                "action": "Ensure authentication is configured",
                "severity": "high"
            },
            {
                "category": "API",
                "change": "Type mappings have been removed",
                "action": "Remove _type from queries and mappings",
                "severity": "high"
            },
            {
                "category": "Settings",
                "change": "node.max_local_storage_nodes removed",
                "action": "Remove from elasticsearch.yml if present",
                "severity": "medium"
            },
            {
                "category": "Templates",
                "change": "Legacy index templates deprecated",
                "action": "Migrate to composable templates",
                "severity": "medium"
            },
            {
                "category": "ILM",
                "change": "freeze action in ILM deprecated",
                "action": "Remove freeze actions from ILM policies",
                "severity": "low"
            },
            {
                "category": "Scripting",
                "change": "Painless context changes",
                "action": "Review and test all Painless scripts",
                "severity": "medium"
            },
            {
                "category": "Aggregations",
                "change": "Some aggregation changes",
                "action": "Review aggregation queries for deprecated features",
                "severity": "low"
            },
            {
                "category": "Java",
                "change": "Minimum Java version is 17",
                "action": "Upgrade Java to version 17 or later",
                "severity": "critical"
            }
        ],
        "6_to_7": [
            {
                "category": "Mappings",
                "change": "Default number of shards changed from 5 to 1",
                "action": "Explicitly set shard count in templates",
                "severity": "medium"
            },
            {
                "category": "Types",
                "change": "Multiple types per index removed",
                "action": "Reindex data with single type",
                "severity": "high"
            },
            {
                "category": "API",
                "change": "_all field disabled by default",
                "action": "Use copy_to for similar functionality",
                "severity": "medium"
            }
        ],
        "8_to_9": [
            {
                "category": "Java",
                "change": "Minimum Java version is 21",
                "action": "Upgrade Java to version 21 or later",
                "severity": "critical"
            },
            {
                "category": "Security",
                "change": "TLS is required for all inter-node communication",
                "action": "Ensure TLS certificates are properly configured for all nodes",
                "severity": "critical"
            },
            {
                "category": "API",
                "change": "Several deprecated REST APIs have been removed",
                "action": "Review and update API calls to use supported endpoints",
                "severity": "high"
            },
            {
                "category": "Mapping",
                "change": "Legacy mapping parameters removed",
                "action": "Update index templates to remove deprecated mapping parameters",
                "severity": "high"
            },
            {
                "category": "Settings",
                "change": "Several deprecated cluster and node settings removed",
                "action": "Review and remove deprecated settings from elasticsearch.yml",
                "severity": "high"
            },
            {
                "category": "Indices",
                "change": "Indices created in 7.x require reindexing",
                "action": "Reindex any indices created before 8.0 before upgrading to 9.x",
                "severity": "critical"
            },
            {
                "category": "Plugins",
                "change": "Plugin architecture changes",
                "action": "Update all third-party plugins to 9.x compatible versions",
                "severity": "high"
            },
            {
                "category": "ILM",
                "change": "Frozen tier removed",
                "action": "Migrate frozen tier data to cold or warm tiers",
                "severity": "medium"
            },
            {
                "category": "Query DSL",
                "change": "Some query types deprecated or removed",
                "action": "Review and update search queries for compatibility",
                "severity": "medium"
            },
            {
                "category": "Scripting",
                "change": "Painless language updates and deprecated methods removed",
                "action": "Review and test all Painless scripts",
                "severity": "medium"
            },
            {
                "category": "Ingest",
                "change": "Some ingest processors behavior changes",
                "action": "Review ingest pipelines for deprecated processor options",
                "severity": "medium"
            },
            {
                "category": "ML",
                "change": "Machine Learning API changes",
                "action": "Update ML job configurations and API calls",
                "severity": "medium"
            }
        ]
    }

    # Minimum versions for direct upgrade
    MINIMUM_VERSIONS = {
        "8.0": Version.parse("7.17.0"),
        "8.1": Version.parse("7.17.0"),
        "7.0": Version.parse("6.8.0"),
        # ES 9.x requires 8.18.0 minimum for direct upgrade
        "9.0": Version.parse("8.18.0"),
        "9.1": Version.parse("8.18.0"),
    }

    def __init__(self, es_client, config):
        """
        Initialize the compatibility checker.

        Args:
            es_client: ElasticsearchClient instance
            config: ConfigManager instance
        """
        self.es = es_client
        self.config = config
        self.logger = logging.getLogger(__name__)

    def check_compatibility(self) -> CompatibilityResult:
        """
        Check compatibility between current and target versions.

        Returns:
            CompatibilityResult with detailed analysis.
        """
        current_str = self.es.get_version()
        target_str = self.config.upgrade.target_version

        try:
            current = Version.parse(current_str)
            target = Version.parse(target_str)
        except ValueError as e:
            return CompatibilityResult(
                compatible=False,
                upgrade_type=UpgradeType.NOT_SUPPORTED,
                upgrade_path=[],
                warnings=[],
                blockers=[f"Invalid version format: {e}"],
                recommendations=[],
                breaking_changes=[]
            )

        # Same version
        if current == target:
            return CompatibilityResult(
                compatible=True,
                upgrade_type=UpgradeType.MINOR,
                upgrade_path=[str(current)],
                warnings=["Current version matches target version - no upgrade needed"],
                blockers=[],
                recommendations=[],
                breaking_changes=[]
            )

        # Downgrade attempt
        if current > target:
            return CompatibilityResult(
                compatible=False,
                upgrade_type=UpgradeType.NOT_SUPPORTED,
                upgrade_path=[],
                warnings=[],
                blockers=["Downgrading Elasticsearch is not supported"],
                recommendations=["Use snapshot restore to revert to a previous version"],
                breaking_changes=[]
            )

        # Determine upgrade type and path
        upgrade_type = self._determine_upgrade_type(current, target)
        upgrade_path = self._calculate_upgrade_path(current, target)
        breaking_changes = self._get_breaking_changes(current, target)
        warnings = self._get_warnings(current, target, upgrade_type)
        blockers = self._get_blockers(current, target)
        recommendations = self._get_recommendations(current, target, upgrade_type)

        compatible = len(blockers) == 0 and upgrade_type != UpgradeType.NOT_SUPPORTED

        return CompatibilityResult(
            compatible=compatible,
            upgrade_type=upgrade_type,
            upgrade_path=upgrade_path,
            warnings=warnings,
            blockers=blockers,
            recommendations=recommendations,
            breaking_changes=breaking_changes
        )

    def _determine_upgrade_type(self, current: Version, target: Version) -> UpgradeType:
        """Determine the type of upgrade required.

        Supports:
        - Minor upgrades (same major version)
        - Single major upgrades (7.x -> 8.x, 8.x -> 9.x)
        - Double major upgrades (7.x -> 9.x) with intermediate steps
        """
        # Same major version - minor upgrade
        if current.major == target.major:
            if target.minor - current.minor <= 1:
                return UpgradeType.ROLLING
            else:
                return UpgradeType.ROLLING  # Minor versions support rolling upgrades

        # Major version upgrade (e.g., 7.x -> 8.x or 8.x -> 9.x)
        if target.major - current.major == 1:
            # Check if direct upgrade is supported
            min_version = self.MINIMUM_VERSIONS.get(f"{target.major}.0")
            if min_version and current >= min_version:
                return UpgradeType.ROLLING
            else:
                return UpgradeType.MAJOR

        # Double major version upgrade (e.g., 7.x -> 9.x)
        # Supported with intermediate steps (7.17 -> 8.18 -> 9.x)
        if target.major - current.major == 2:
            return UpgradeType.DOUBLE_MAJOR

        # More than 2 major versions - requires reindexing
        if target.major - current.major > 2:
            return UpgradeType.REINDEX

        return UpgradeType.NOT_SUPPORTED

    def _calculate_upgrade_path(self, current: Version, target: Version) -> List[str]:
        """Calculate the upgrade path from current to target version.

        Handles single and double major upgrades:
        - 7.x -> 8.x: Direct upgrade (requires 7.17.x minimum)
        - 8.x -> 9.x: Direct upgrade (requires 8.18.x minimum)
        - 7.x -> 9.x: Double upgrade through 7.17.x -> 8.18.x -> 9.x
        """
        path = [str(current)]

        # Direct upgrade within same major
        if current.major == target.major:
            path.append(str(target))
            return path

        # Major version upgrade (e.g., 7.x -> 8.x or 8.x -> 9.x)
        if target.major - current.major == 1:
            # Upgrade to last minor of current major if needed
            last_minor = self._get_last_minor_version(current.major)
            if current.minor < last_minor:
                path.append(f"{current.major}.{last_minor}.x")

            path.append(str(target))
            return path

        # Double major version upgrade (e.g., 7.x -> 9.x)
        if target.major - current.major == 2:
            # Step 1: Upgrade to last minor of current major if needed
            last_minor_current = self._get_last_minor_version(current.major)
            if current.minor < last_minor_current:
                path.append(f"{current.major}.{last_minor_current}.x")

            # Step 2: Upgrade to last minor of intermediate major version
            intermediate_major = current.major + 1
            last_minor_intermediate = self._get_last_minor_version(intermediate_major)
            path.append(f"{intermediate_major}.{last_minor_intermediate}.x")

            # Step 3: Final upgrade to target
            path.append(str(target))
            return path

        # More than 2 major versions - need multiple intermediate steps
        if target.major - current.major > 2:
            intermediate = current.major
            while intermediate < target.major:
                last_minor = self._get_last_minor_version(intermediate)
                if intermediate > current.major or current.minor < last_minor:
                    path.append(f"{intermediate}.{last_minor}.x")
                intermediate += 1
            path.append(str(target))

        return path

    def _get_last_minor_version(self, major: int) -> int:
        """Get the last minor version of a major release."""
        last_minor_map = {
            6: 8,
            7: 17,
            8: 18,  # 8.18 is the last minor before 9.x
            9: 1    # Update as new versions are released
        }
        return last_minor_map.get(major, 0)

    def _get_breaking_changes(self, current: Version, target: Version) -> List[Dict[str, str]]:
        """Get breaking changes between versions.

        For double upgrades (e.g., 7 -> 9), this returns all breaking changes
        for both transitions (7 -> 8 and 8 -> 9).
        """
        changes = []

        if current.major == 6 and target.major >= 7:
            changes.extend(self.BREAKING_CHANGES.get("6_to_7", []))

        if current.major <= 7 and target.major >= 8:
            changes.extend(self.BREAKING_CHANGES.get("7_to_8", []))

        if current.major <= 8 and target.major >= 9:
            changes.extend(self.BREAKING_CHANGES.get("8_to_9", []))

        return changes

    def _get_warnings(self, current: Version, target: Version, upgrade_type: UpgradeType) -> List[str]:
        """Get warnings for the upgrade."""
        warnings = []

        if upgrade_type == UpgradeType.MAJOR:
            warnings.append(f"Major version upgrade from {current.major}.x to {target.major}.x requires careful planning")

        if upgrade_type == UpgradeType.REINDEX:
            warnings.append("Upgrade requires reindexing data - this can be time-consuming")

        # Double upgrade warning (e.g., 7.x -> 9.x)
        if upgrade_type == UpgradeType.DOUBLE_MAJOR:
            warnings.append(f"Double major version upgrade detected: {current.major}.x -> {target.major}.x")
            warnings.append("This requires two sequential upgrades with cluster restarts")
            warnings.append("Plan for extended maintenance window")

        if target.major == 8 and current.major == 7:
            warnings.append("Elasticsearch 8.x enables security by default")
            warnings.append("Review and test all custom scripts before upgrade")
            warnings.append("Legacy index templates should be migrated to composable templates")

        if target.major == 9 and current.major == 8:
            warnings.append("Elasticsearch 9.x requires Java 21 or later")
            warnings.append("TLS is mandatory for all inter-node communication")
            warnings.append("Indices created in 7.x must be reindexed before upgrading to 9.x")
            warnings.append("Review all deprecated settings and APIs")

        # Double upgrade 7 -> 9: combine warnings
        if target.major == 9 and current.major == 7:
            warnings.append("Elasticsearch 8.x enables security by default")
            warnings.append("Legacy index templates must be migrated to composable templates")
            warnings.append("Elasticsearch 9.x requires Java 21 or later")
            warnings.append("TLS is mandatory for all inter-node communication in 9.x")
            warnings.append("All indices from 7.x need reindexing before reaching 9.x")

        if current.minor < self._get_last_minor_version(current.major):
            warnings.append(f"Consider upgrading to {current.major}.{self._get_last_minor_version(current.major)}.x first")

        return warnings

    def _get_blockers(self, current: Version, target: Version) -> List[str]:
        """Get upgrade blockers.

        Note: Double upgrades (e.g., 7.x -> 9.x) are supported with intermediate steps.
        Only upgrades spanning more than 2 major versions are blocked.
        """
        blockers = []

        # Check for unsupported direct upgrades (more than 2 major versions)
        if target.major - current.major > 2:
            blockers.append(f"Direct upgrade from {current.major}.x to {target.major}.x is not supported")
            blockers.append("Must upgrade through intermediate major versions")

        # Check minimum version requirements for 7 -> 8
        if target.major == 8 and current.major == 7 and current < Version.parse("7.17.0"):
            blockers.append(f"Must upgrade to 7.17.x before upgrading to 8.x (current: {current})")

        # Check minimum version requirements for 8 -> 9
        if target.major == 9 and current.major == 8 and current < Version.parse("8.18.0"):
            blockers.append(f"Must upgrade to 8.18.x before upgrading to 9.x (current: {current})")

        # Check minimum version requirements for double upgrade 7 -> 9
        if target.major == 9 and current.major == 7:
            if current < Version.parse("7.17.0"):
                blockers.append(f"Must upgrade to 7.17.x first before proceeding (current: {current})")
            # This is a warning, not a blocker - the path will include intermediate steps

        if target.major == 7 and current.major == 6 and current < Version.parse("6.8.0"):
            blockers.append(f"Must upgrade to 6.8.x before upgrading to 7.x (current: {current})")

        return blockers

    def _get_recommendations(self, current: Version, target: Version, upgrade_type: UpgradeType) -> List[str]:
        """Get upgrade recommendations."""
        recommendations = [
            "Create a full cluster snapshot before starting the upgrade",
            "Review the official Elasticsearch upgrade guide",
            "Test the upgrade in a non-production environment first"
        ]

        if upgrade_type == UpgradeType.ROLLING:
            recommendations.extend([
                "Use rolling upgrade to minimize downtime",
                "Upgrade one node at a time, starting with non-master-eligible nodes",
                "Wait for cluster health to be GREEN before proceeding to next node"
            ])

        if upgrade_type == UpgradeType.MAJOR:
            recommendations.extend([
                "Review all breaking changes carefully",
                "Update client applications for API compatibility",
                "Test all integrations with the new version"
            ])

        # Double upgrade recommendations (e.g., 7 -> 9)
        if upgrade_type == UpgradeType.DOUBLE_MAJOR:
            recommendations.extend([
                "Plan for two sequential upgrades with separate snapshots",
                "Create snapshot before each major upgrade step",
                "Validate cluster health after each upgrade step",
                "Allow sufficient time for each upgrade phase"
            ])

        if target.major == 8:
            recommendations.extend([
                "Plan for security configuration (TLS, authentication)",
                "Update Kibana and other Elastic stack components",
                "Review and migrate legacy index templates"
            ])

        if target.major == 9:
            recommendations.extend([
                "Upgrade Java to version 21 or later before upgrading",
                "Ensure TLS certificates are configured for all nodes",
                "Update Kibana to 9.x (matching minor version)",
                "Update all Elastic Stack components (Logstash, Beats, etc.)",
                "Review and update all third-party plugins",
                "Check for indices created before 8.0 and reindex if needed",
                "Test all ingest pipelines and transforms",
                "Review Machine Learning job configurations"
            ])

        # Specific recommendations for double upgrade 7 -> 9
        if target.major == 9 and current.major == 7:
            recommendations.extend([
                "Phase 1: Complete upgrade to 8.18.x and validate all features",
                "Phase 2: After validation, proceed with upgrade to 9.x",
                "Reindex all data from 7.x indices before upgrading to 9.x",
                "Update all client libraries and application code",
                "Consider extended maintenance window for double upgrade"
            ])

        return recommendations

    def get_upgrade_path_summary(self) -> str:
        """Get a human-readable summary of the upgrade path."""
        result = self.check_compatibility()

        if not result.compatible:
            return f"Upgrade NOT compatible: {'; '.join(result.blockers)}"

        path_str = " -> ".join(result.upgrade_path)
        return f"Upgrade path: {path_str} ({result.upgrade_type.value} upgrade)"

    def check_index_compatibility(self, index_name: str) -> Dict[str, Any]:
        """
        Check if a specific index is compatible with the target version.

        Args:
            index_name: Name of the index to check.

        Returns:
            Dictionary with compatibility information.
        """
        target = Version.parse(self.config.upgrade.target_version)

        # Get index settings and mappings
        try:
            settings = self.es.client.indices.get_settings(index=index_name)
            mappings = self.es.client.indices.get_mapping(index=index_name)

            issues = []
            warnings = []

            # Check for deprecated mapping types
            index_mappings = mappings.get(index_name, {}).get("mappings", {})
            if "_type" in str(index_mappings):
                issues.append("Index uses deprecated _type field")

            # Check for _all field
            if "_all" in str(index_mappings):
                warnings.append("Index uses _all field which is deprecated")

            # Check created version if available
            index_settings = settings.get(index_name, {}).get("settings", {}).get("index", {})
            created_version = index_settings.get("version", {}).get("created_string", "")

            if created_version:
                try:
                    created = Version.parse(created_version.split("-")[0])
                    if target.major - created.major > 1:
                        issues.append(f"Index was created in version {created_version} - may need reindexing")
                except ValueError:
                    pass

            return {
                "index": index_name,
                "compatible": len(issues) == 0,
                "issues": issues,
                "warnings": warnings,
                "created_version": created_version
            }

        except Exception as e:
            return {
                "index": index_name,
                "compatible": False,
                "issues": [f"Failed to check index: {e}"],
                "warnings": [],
                "created_version": ""
            }

    def check_all_indices_compatibility(self) -> List[Dict[str, Any]]:
        """
        Check compatibility of all indices.

        Returns:
            List of compatibility results for each index.
        """
        indices = self.es.get_indices_info()
        results = []

        for index_info in indices:
            if "error" in index_info:
                continue

            index_name = index_info.get("index", "")
            if index_name.startswith("."):  # Skip system indices
                continue

            result = self.check_index_compatibility(index_name)
            results.append(result)

        return results

    def check_kibana_compatibility(self, kibana_version: str) -> Dict[str, Any]:
        """
        Check Kibana version compatibility with target Elasticsearch version.

        Args:
            kibana_version: Current Kibana version.

        Returns:
            Dictionary with compatibility information.
        """
        target = Version.parse(self.config.upgrade.target_version)

        try:
            kibana = Version.parse(kibana_version)
        except ValueError:
            return {
                "compatible": False,
                "message": f"Invalid Kibana version: {kibana_version}"
            }

        # Kibana must match Elasticsearch major.minor version
        if kibana.major != target.major or kibana.minor != target.minor:
            return {
                "compatible": False,
                "current_kibana": str(kibana),
                "required_kibana": f"{target.major}.{target.minor}.x",
                "message": f"Kibana must be upgraded to {target.major}.{target.minor}.x"
            }

        return {
            "compatible": True,
            "current_kibana": str(kibana),
            "message": "Kibana version is compatible"
        }

    def check_logstash_compatibility(self, logstash_version: str) -> Dict[str, Any]:
        """
        Check Logstash version compatibility with target Elasticsearch version.

        Args:
            logstash_version: Current Logstash version.

        Returns:
            Dictionary with compatibility information.
        """
        target = Version.parse(self.config.upgrade.target_version)

        try:
            logstash = Version.parse(logstash_version)
        except ValueError:
            return {
                "compatible": False,
                "message": f"Invalid Logstash version: {logstash_version}"
            }

        # Logstash should match Elasticsearch major version
        if logstash.major != target.major:
            return {
                "compatible": False,
                "current_logstash": str(logstash),
                "required_logstash": f"{target.major}.x.x",
                "message": f"Logstash should be upgraded to {target.major}.x.x"
            }

        return {
            "compatible": True,
            "current_logstash": str(logstash),
            "message": "Logstash version is compatible"
        }
