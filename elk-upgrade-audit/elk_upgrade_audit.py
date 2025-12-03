#!/usr/bin/env python3
"""
ELK Upgrade Audit Tool
======================
A comprehensive tool for auditing and managing Elasticsearch cluster upgrades.

Usage:
    python elk_upgrade_audit.py [command] [options]

Commands:
    audit       Run pre-upgrade audit
    compat      Check version compatibility
    backup      Manage snapshots/backups
    upgrade     Manage upgrade process
    validate    Run post-upgrade validation
    report      Generate reports
    interactive Interactive mode

Example:
    python elk_upgrade_audit.py audit --target-version 8.11.0
    python elk_upgrade_audit.py interactive
"""

import argparse
import sys
import logging
from pathlib import Path

# Add modules to path
sys.path.insert(0, str(Path(__file__).parent))

from modules.config import ConfigManager, setup_logging
from modules.elasticsearch_client import ElasticsearchClient
from modules.pre_upgrade_audit import PreUpgradeAudit, CheckStatus
from modules.compatibility_checker import CompatibilityChecker
from modules.snapshot_manager import SnapshotManager
from modules.upgrade_orchestrator import UpgradeOrchestrator, UpgradePhase
from modules.post_upgrade_validator import PostUpgradeValidator
from modules.report_generator import ReportGenerator


class ElkUpgradeAuditCLI:
    """
    Command-line interface for the ELK Upgrade Audit Tool.
    """

    def __init__(self, config_path: str = None):
        """Initialize the CLI."""
        self.config = ConfigManager(config_path)
        self.config.load()
        self.es_client = None
        self.logger = logging.getLogger(__name__)

    def connect(self) -> bool:
        """Establish connection to Elasticsearch."""
        self.es_client = ElasticsearchClient(self.config.elasticsearch)
        return self.es_client.connect()

    def run_audit(self, args):
        """Run pre-upgrade audit."""
        print("\n" + "=" * 60)
        print("ELK PRE-UPGRADE AUDIT")
        print("=" * 60 + "\n")

        if not self.connect():
            print("ERROR: Failed to connect to Elasticsearch")
            return 1

        # Update target version if provided
        if args.target_version:
            self.config.upgrade.target_version = args.target_version

        print(f"Cluster: {self.es_client.cluster_info.get('cluster_name')}")
        print(f"Current Version: {self.es_client.get_version()}")
        print(f"Target Version: {self.config.upgrade.target_version}")
        print("-" * 60)

        # Run pre-upgrade audit
        audit = PreUpgradeAudit(self.es_client, self.config)
        report = audit.run_full_audit()

        # Run compatibility check
        compat_checker = CompatibilityChecker(self.es_client, self.config)
        compat_result = compat_checker.check_compatibility()

        # Print results
        print("\n" + "-" * 60)
        print("AUDIT SUMMARY")
        print("-" * 60)
        self._print_check_summary(report)

        print("\n" + "-" * 60)
        print("COMPATIBILITY")
        print("-" * 60)
        self._print_compatibility(compat_result)

        # Generate report if requested
        if args.output:
            generator = ReportGenerator(args.output)
            report_path = generator.generate_pre_upgrade_report(
                report, compat_result, format=args.format
            )
            print(f"\nReport saved to: {report_path}")

        # Print final status
        print("\n" + "=" * 60)
        if report.ready_for_upgrade and compat_result.compatible:
            print("STATUS: READY FOR UPGRADE")
        else:
            print("STATUS: NOT READY FOR UPGRADE")
            if audit.get_upgrade_blockers():
                print("\nBlockers:")
                for blocker in audit.get_upgrade_blockers():
                    print(f"  - {blocker.message}")
        print("=" * 60)

        return 0 if report.ready_for_upgrade else 1

    def run_compatibility(self, args):
        """Run compatibility check."""
        print("\n" + "=" * 60)
        print("VERSION COMPATIBILITY CHECK")
        print("=" * 60 + "\n")

        if not self.connect():
            print("ERROR: Failed to connect to Elasticsearch")
            return 1

        if args.target_version:
            self.config.upgrade.target_version = args.target_version

        checker = CompatibilityChecker(self.es_client, self.config)
        result = checker.check_compatibility()

        self._print_compatibility(result)

        # Check index compatibility if requested
        if args.check_indices:
            print("\n" + "-" * 60)
            print("INDEX COMPATIBILITY")
            print("-" * 60)
            indices = checker.check_all_indices_compatibility()
            incompatible = [i for i in indices if not i.get("compatible")]

            if incompatible:
                print(f"\n{len(incompatible)} incompatible index(es) found:")
                for idx in incompatible[:10]:
                    print(f"  - {idx.get('index')}: {', '.join(idx.get('issues', []))}")
            else:
                print("\nAll indices are compatible")

        return 0 if result.compatible else 1

    def run_backup(self, args):
        """Manage backups/snapshots."""
        print("\n" + "=" * 60)
        print("SNAPSHOT MANAGEMENT")
        print("=" * 60 + "\n")

        if not self.connect():
            print("ERROR: Failed to connect to Elasticsearch")
            return 1

        manager = SnapshotManager(self.es_client, self.config)

        if args.action == "list":
            repos = manager.list_repositories()
            if repos:
                print("Snapshot Repositories:")
                for repo in repos:
                    print(f"\n  {repo['name']} ({repo['type']})")
                    snapshots = manager.list_snapshots(repo['name'])
                    if snapshots:
                        print(f"    Snapshots: {len(snapshots)}")
                        for snap in snapshots[:5]:
                            print(f"      - {snap.name} ({snap.state.value})")
            else:
                print("No snapshot repositories configured")

        elif args.action == "create":
            print("Creating pre-upgrade snapshot...")
            result = manager.create_pre_upgrade_snapshot(wait_for_completion=True)
            if result.get("success"):
                print(f"Snapshot created: {result.get('snapshot_name')}")
            else:
                print(f"Failed to create snapshot: {result.get('error')}")
                return 1

        elif args.action == "check":
            readiness = manager.check_backup_readiness()
            print(f"Backup Readiness: {'READY' if readiness['ready'] else 'NOT READY'}")
            if readiness.get("issues"):
                print("\nIssues:")
                for issue in readiness["issues"]:
                    print(f"  - {issue}")
            if readiness.get("warnings"):
                print("\nWarnings:")
                for warning in readiness["warnings"]:
                    print(f"  - {warning}")

        return 0

    def run_upgrade(self, args):
        """Manage upgrade process."""
        print("\n" + "=" * 60)
        print("UPGRADE ORCHESTRATION")
        print("=" * 60 + "\n")

        if not self.connect():
            print("ERROR: Failed to connect to Elasticsearch")
            return 1

        if args.target_version:
            self.config.upgrade.target_version = args.target_version

        # Initialize components
        snapshot_manager = SnapshotManager(self.es_client, self.config)
        pre_audit = PreUpgradeAudit(self.es_client, self.config)
        post_validator = PostUpgradeValidator(self.es_client, self.config)

        orchestrator = UpgradeOrchestrator(
            self.es_client, self.config,
            snapshot_manager=snapshot_manager,
            pre_upgrade_audit=pre_audit,
            post_upgrade_validator=post_validator
        )

        if args.action == "plan":
            orchestrator.initialize_upgrade()
            plan = orchestrator.get_upgrade_plan()

            print(f"Upgrade ID: {plan['upgrade_id']}")
            print(f"Strategy: {plan['strategy']}")
            print(f"Target Version: {plan['target_version']}")
            print(f"\nUpgrade Phases:")
            for i, phase in enumerate(plan['phases'], 1):
                print(f"  {i}. {phase['description']} [{phase['phase']}]")

            print(f"\nNode Upgrade Order:")
            for i, node in enumerate(plan['node_upgrade_order'], 1):
                print(f"  {i}. {node['node_name']} ({node['role']}) - {node['version']}")

        elif args.action == "status":
            status = orchestrator.get_current_status()
            print(f"Status: {status.get('status', 'unknown')}")
            if status.get('current_phase'):
                print(f"Current Phase: {status['current_phase']}")

        elif args.action == "execute":
            if args.phase:
                phase = UpgradePhase[args.phase.upper()]
                result = orchestrator.execute_phase(phase)
                print(f"Phase {phase.value}: {'Success' if result.get('success') else 'Failed'}")
                if not result.get('success'):
                    print(f"Error: {result.get('error')}")
            else:
                print("Specify a phase with --phase")
                return 1

        elif args.action == "rollback":
            instructions = orchestrator.get_rollback_instructions()
            print("\n".join(instructions))

        return 0

    def run_validate(self, args):
        """Run post-upgrade validation."""
        print("\n" + "=" * 60)
        print("POST-UPGRADE VALIDATION")
        print("=" * 60 + "\n")

        if not self.connect():
            print("ERROR: Failed to connect to Elasticsearch")
            return 1

        validator = PostUpgradeValidator(self.es_client, self.config)
        report = validator.run_validation()

        # Print results
        print(f"Cluster: {report.cluster_name}")
        print(f"Version: {report.version}")
        print(f"Duration: {report.total_duration_ms}ms")
        print("-" * 60)

        for check in report.checks:
            status_symbol = {
                "passed": "[OK]",
                "warning": "[WARN]",
                "failed": "[FAIL]",
                "skipped": "[SKIP]"
            }.get(check.status.value, "[?]")
            print(f"{status_symbol} {check.name}: {check.message}")

        print("-" * 60)
        print(f"\nPassed: {report.summary.get('passed', 0)}")
        print(f"Warnings: {report.summary.get('warning', 0)}")
        print(f"Failed: {report.summary.get('failed', 0)}")

        # Generate report if requested
        if args.output:
            generator = ReportGenerator(args.output)
            report_path = generator.generate_post_upgrade_report(
                report, format=args.format
            )
            print(f"\nReport saved to: {report_path}")

        print("\n" + "=" * 60)
        print(f"VALIDATION: {'PASSED' if report.passed else 'FAILED'}")
        print("=" * 60)

        return 0 if report.passed else 1

    def run_interactive(self, args):
        """Run interactive mode."""
        print("\n" + "=" * 60)
        print("ELK UPGRADE AUDIT TOOL - INTERACTIVE MODE")
        print("=" * 60 + "\n")

        if not self.connect():
            print("ERROR: Failed to connect to Elasticsearch")
            return 1

        print(f"Connected to: {self.es_client.cluster_info.get('cluster_name')}")
        print(f"Version: {self.es_client.get_version()}")
        print("\nAvailable commands:")
        print("  1. audit     - Run pre-upgrade audit")
        print("  2. compat    - Check version compatibility")
        print("  3. backup    - Manage snapshots")
        print("  4. upgrade   - View upgrade plan")
        print("  5. validate  - Run post-upgrade validation")
        print("  6. health    - Show cluster health")
        print("  7. nodes     - Show node information")
        print("  8. indices   - Show index information")
        print("  9. quit      - Exit")
        print()

        while True:
            try:
                choice = input("\nEnter command (1-9): ").strip().lower()

                if choice in ['9', 'quit', 'exit', 'q']:
                    print("Goodbye!")
                    break

                elif choice in ['1', 'audit']:
                    target = input("Target version (default: 8.11.0): ").strip() or "8.11.0"
                    self.config.upgrade.target_version = target
                    audit = PreUpgradeAudit(self.es_client, self.config)
                    report = audit.run_full_audit()
                    self._print_check_summary(report)

                elif choice in ['2', 'compat']:
                    target = input("Target version (default: 8.11.0): ").strip() or "8.11.0"
                    self.config.upgrade.target_version = target
                    checker = CompatibilityChecker(self.es_client, self.config)
                    result = checker.check_compatibility()
                    self._print_compatibility(result)

                elif choice in ['3', 'backup']:
                    manager = SnapshotManager(self.es_client, self.config)
                    readiness = manager.check_backup_readiness()
                    print(f"\nBackup Readiness: {'READY' if readiness['ready'] else 'NOT READY'}")
                    if readiness.get('repositories'):
                        print(f"Repositories: {', '.join(r['name'] for r in readiness['repositories'])}")

                elif choice in ['4', 'upgrade']:
                    target = input("Target version (default: 8.11.0): ").strip() or "8.11.0"
                    self.config.upgrade.target_version = target
                    orchestrator = UpgradeOrchestrator(self.es_client, self.config)
                    orchestrator.initialize_upgrade()
                    plan = orchestrator.get_upgrade_plan()
                    print(f"\nUpgrade Plan to {plan['target_version']}:")
                    for i, phase in enumerate(plan['phases'], 1):
                        print(f"  {i}. {phase['description']}")

                elif choice in ['5', 'validate']:
                    validator = PostUpgradeValidator(self.es_client, self.config)
                    report = validator.run_validation()
                    print(f"\nValidation: {'PASSED' if report.passed else 'FAILED'}")
                    print(f"Passed: {report.summary.get('passed')}, Failed: {report.summary.get('failed')}")

                elif choice in ['6', 'health']:
                    health = self.es_client.get_cluster_health()
                    print(f"\nCluster Health: {health.get('status', 'unknown').upper()}")
                    print(f"Nodes: {health.get('number_of_nodes')}")
                    print(f"Data Nodes: {health.get('number_of_data_nodes')}")
                    print(f"Active Shards: {health.get('active_shards')}")
                    print(f"Unassigned Shards: {health.get('unassigned_shards')}")

                elif choice in ['7', 'nodes']:
                    nodes = self.es_client.get_nodes_info()
                    print("\nCluster Nodes:")
                    for node in nodes:
                        if "error" not in node:
                            print(f"  - {node.get('name')} ({node.get('version')}) - {', '.join(node.get('roles', []))}")

                elif choice in ['8', 'indices']:
                    indices = self.es_client.get_indices_info()
                    print(f"\nIndices ({len(indices)} total):")
                    for idx in indices[:20]:
                        if "error" not in idx:
                            size_mb = idx.get('store_size', 0) / (1024*1024)
                            print(f"  - {idx.get('index')} [{idx.get('health')}] - {size_mb:.1f}MB, {idx.get('docs_count')} docs")
                    if len(indices) > 20:
                        print(f"  ... and {len(indices) - 20} more")

                else:
                    print("Invalid choice. Please enter 1-9.")

            except KeyboardInterrupt:
                print("\n\nExiting...")
                break
            except Exception as e:
                print(f"Error: {e}")

        return 0

    def _print_check_summary(self, report):
        """Print audit check summary."""
        print(f"\nPassed: {report.summary.get('passed', 0)}")
        print(f"Warnings: {report.summary.get('warning', 0)}")
        print(f"Failed: {report.summary.get('failed', 0)}")
        print(f"\nReady for Upgrade: {'Yes' if report.ready_for_upgrade else 'No'}")

    def _print_compatibility(self, result):
        """Print compatibility check results."""
        print(f"Compatible: {'Yes' if result.compatible else 'No'}")
        print(f"Upgrade Type: {result.upgrade_type.value}")
        print(f"Upgrade Path: {' -> '.join(result.upgrade_path)}")

        if result.blockers:
            print("\nBlockers:")
            for blocker in result.blockers:
                print(f"  - {blocker}")

        if result.warnings:
            print("\nWarnings:")
            for warning in result.warnings[:5]:
                print(f"  - {warning}")

        if result.breaking_changes:
            print(f"\nBreaking Changes: {len(result.breaking_changes)}")
            for change in result.breaking_changes[:3]:
                print(f"  - [{change.get('category')}] {change.get('change')}")


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="ELK Upgrade Audit Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__
    )

    parser.add_argument(
        "-c", "--config",
        help="Path to configuration file",
        default=None
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Enable verbose output"
    )

    subparsers = parser.add_subparsers(dest="command", help="Command to run")

    # Audit command
    audit_parser = subparsers.add_parser("audit", help="Run pre-upgrade audit")
    audit_parser.add_argument("--target-version", help="Target Elasticsearch version")
    audit_parser.add_argument("--output", "-o", help="Output directory for reports")
    audit_parser.add_argument("--format", "-f", choices=["html", "json", "markdown"],
                             default="html", help="Report format")

    # Compatibility command
    compat_parser = subparsers.add_parser("compat", help="Check version compatibility")
    compat_parser.add_argument("--target-version", help="Target Elasticsearch version")
    compat_parser.add_argument("--check-indices", action="store_true",
                              help="Check index compatibility")

    # Backup command
    backup_parser = subparsers.add_parser("backup", help="Manage snapshots/backups")
    backup_parser.add_argument("action", choices=["list", "create", "check"],
                              help="Backup action to perform")

    # Upgrade command
    upgrade_parser = subparsers.add_parser("upgrade", help="Manage upgrade process")
    upgrade_parser.add_argument("action", choices=["plan", "status", "execute", "rollback"],
                               help="Upgrade action to perform")
    upgrade_parser.add_argument("--target-version", help="Target Elasticsearch version")
    upgrade_parser.add_argument("--phase", help="Phase to execute")

    # Validate command
    validate_parser = subparsers.add_parser("validate", help="Run post-upgrade validation")
    validate_parser.add_argument("--output", "-o", help="Output directory for reports")
    validate_parser.add_argument("--format", "-f", choices=["html", "json", "markdown"],
                                default="html", help="Report format")

    # Interactive command
    subparsers.add_parser("interactive", help="Run in interactive mode")

    args = parser.parse_args()

    # Setup logging
    log_level = "DEBUG" if args.verbose else "INFO"
    setup_logging(level=log_level)

    # Create CLI instance
    cli = ElkUpgradeAuditCLI(args.config)

    # Run appropriate command
    if args.command == "audit":
        return cli.run_audit(args)
    elif args.command == "compat":
        return cli.run_compatibility(args)
    elif args.command == "backup":
        return cli.run_backup(args)
    elif args.command == "upgrade":
        return cli.run_upgrade(args)
    elif args.command == "validate":
        return cli.run_validate(args)
    elif args.command == "interactive":
        return cli.run_interactive(args)
    else:
        # Default to interactive mode
        return cli.run_interactive(args)


if __name__ == "__main__":
    sys.exit(main())
