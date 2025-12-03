#!/usr/bin/env python3
"""
AI Monitoring & Observability Platform
======================================

Command-line interface for the AI monitoring platform.

Usage:
    python ai_monitoring.py setup           # Set up indices and templates
    python ai_monitoring.py status          # Show monitoring status
    python ai_monitoring.py alerts          # Show active alerts
    python ai_monitoring.py summary         # Show metrics summary
    python ai_monitoring.py collect         # Start metrics collection daemon
    python ai_monitoring.py demo            # Run demo with sample data
    python ai_monitoring.py interactive     # Interactive mode
"""

import argparse
import json
import logging
import sys
import time
import uuid
import random
from datetime import datetime, timezone
from pathlib import Path

# Add modules to path
sys.path.insert(0, str(Path(__file__).parent))

from modules.config import Config, load_config
from modules.elasticsearch_client import AIMonitoringClient
from modules.technical_monitor import TechnicalMonitor, RequestStatus
from modules.cognitive_monitor import CognitiveMonitor
from modules.finops_monitor import FinOpsMonitor
from modules.devops_monitor import DevOpsMonitor, HealthStatus
from modules.compliance_monitor import ComplianceMonitor
from modules.metrics_collector import MetricsCollector, AIRequest
from modules.alerting import AlertManager

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


def setup_command(config: Config) -> None:
    """Set up Elasticsearch indices and templates."""
    print("=" * 60)
    print("AI Monitoring Platform - Setup")
    print("=" * 60)

    es_client = AIMonitoringClient(config)

    if not es_client.is_connected():
        print("ERROR: Could not connect to Elasticsearch")
        return

    print("\n[1/3] Installing ILM policies...")
    try:
        ilm_path = Path(__file__).parent / "templates" / "ilm_policies.json"
        results = es_client.install_ilm_policies_from_file(str(ilm_path))
        for name, success in results.items():
            status = "OK" if success else "FAILED"
            print(f"  - {name}: {status}")
    except Exception as e:
        print(f"  ERROR: {e}")

    print("\n[2/3] Installing index templates...")
    try:
        templates_dir = Path(__file__).parent / "templates"
        results = es_client.install_templates_from_directory(str(templates_dir))
        for name, success in results.items():
            status = "OK" if success else "FAILED"
            print(f"  - {name}: {status}")
    except Exception as e:
        print(f"  ERROR: {e}")

    print("\n[3/3] Creating initial indices...")
    try:
        results = es_client.create_initial_indices()
        for name, success in results.items():
            status = "OK" if success else "FAILED"
            print(f"  - {name}: {status}")
    except Exception as e:
        print(f"  ERROR: {e}")

    print("\n" + "=" * 60)
    print("Setup complete!")
    print("=" * 60)


def status_command(config: Config) -> None:
    """Show monitoring status."""
    print("=" * 60)
    print("AI Monitoring Platform - Status")
    print("=" * 60)

    es_client = AIMonitoringClient(config)

    # Connection status
    print("\n[Elasticsearch Connection]")
    if es_client.is_connected():
        health = es_client.get_cluster_health()
        print(f"  Status: Connected")
        print(f"  Cluster: {health.get('cluster_name', 'unknown')}")
        print(f"  Health: {health.get('status', 'unknown').upper()}")
        print(f"  Nodes: {health.get('number_of_nodes', 0)}")
    else:
        print("  Status: DISCONNECTED")
        return

    # Index status
    print("\n[Indices]")
    indices = [
        "ai-technical-metrics",
        "ai-cognitive-metrics",
        "ai-finops-metrics",
        "ai-devops-metrics",
        "ai-compliance-metrics",
    ]
    for index in indices:
        try:
            count = es_client.count_documents(f"{index}-*")
            print(f"  {index}: {count:,} documents")
        except Exception:
            print(f"  {index}: NOT FOUND")

    # Configuration status
    print("\n[Configuration]")
    print(f"  Technical monitoring: {'ENABLED' if config.technical.enabled else 'DISABLED'}")
    print(f"  Cognitive monitoring: {'ENABLED' if config.cognitive.enabled else 'DISABLED'}")
    print(f"  FinOps monitoring: {'ENABLED' if config.finops.enabled else 'DISABLED'}")
    print(f"  DevOps monitoring: {'ENABLED' if config.devops.enabled else 'DISABLED'}")
    print(f"  Compliance monitoring: {'ENABLED' if config.compliance.enabled else 'DISABLED'}")
    print(f"  Alerting: {'ENABLED' if config.alerting.enabled else 'DISABLED'}")


def alerts_command(config: Config) -> None:
    """Show active alerts."""
    print("=" * 60)
    print("AI Monitoring Platform - Active Alerts")
    print("=" * 60)

    alert_manager = AlertManager(config)
    alerts = alert_manager.get_active_alerts()

    if not alerts:
        print("\nNo active alerts.")
        return

    print(f"\nTotal active alerts: {len(alerts)}\n")

    for alert in alerts:
        severity_icon = {
            "critical": "🔴",
            "warning": "🟡",
            "info": "🟢",
        }.get(alert.severity.value, "⚪")

        print(f"{severity_icon} [{alert.severity.value.upper()}] {alert.name}")
        print(f"   Category: {alert.category.value}")
        print(f"   Message: {alert.message}")
        print(f"   Created: {alert.created_at}")
        print(f"   ID: {alert.id}")
        print()


def summary_command(config: Config) -> None:
    """Show metrics summary."""
    print("=" * 60)
    print("AI Monitoring Platform - Metrics Summary")
    print("=" * 60)

    collector = MetricsCollector(config)
    summary = collector.get_summary()

    # Technical metrics
    print("\n[Technical Metrics]")
    tech = summary.get("technical", {})
    latency = tech.get("latency", {})
    print(f"  Latency P50: {latency.get('p50', 0):.2f} ms")
    print(f"  Latency P95: {latency.get('p95', 0):.2f} ms")
    print(f"  Latency P99: {latency.get('p99', 0):.2f} ms")
    print(f"  Error Rate: {tech.get('error_rate', 0):.2f}%")

    # FinOps metrics
    print("\n[FinOps Metrics]")
    finops = summary.get("finops", {})
    cost = finops.get("cost_summary", {})
    daily = cost.get("daily", {})
    print(f"  Daily Spend: ${daily.get('total', 0):.2f}")
    print(f"  Daily Budget: ${daily.get('budget', 0):.2f}")
    print(f"  Usage: {daily.get('percentage_used', 0):.1f}%")

    roi = finops.get("roi_summary", {})
    print(f"  ROI Ratio: {roi.get('roi_ratio', 0):.2f}")

    # Cognitive metrics
    print("\n[Cognitive Metrics]")
    cog = summary.get("cognitive", {})
    print(f"  Average Quality: {cog.get('avg_quality_score', 0):.2f}")
    print(f"  Hallucination Rate: {cog.get('hallucination_rate', 0):.2%}")
    print(f"  Bias Rate: {cog.get('bias_rate', 0):.2%}")
    print(f"  Toxicity Rate: {cog.get('toxicity_rate', 0):.2%}")

    # Compliance metrics
    print("\n[Compliance Metrics]")
    comp = summary.get("compliance", {})
    print(f"  PII Detections: {comp.get('pii_detections', 0)}")
    print(f"  Policy Violations: {comp.get('policy_violations', 0)}")
    print(f"  Approved Models: {comp.get('approved_models', 0)}")

    # DevOps metrics
    print("\n[DevOps Metrics]")
    devops = summary.get("devops", {})
    print(f"  Health: {devops.get('health', 'unknown')}")
    resources = devops.get("resources", {})
    print(f"  CPU: {resources.get('cpu_percent', 0):.1f}%")
    print(f"  Memory: {resources.get('memory_percent', 0):.1f}%")

    # Active alerts
    print("\n[Alerts]")
    alerts = collector.check_alerts()
    print(f"  Active Alerts: {len(alerts)}")
    for alert in alerts[:3]:
        print(f"    - [{alert.get('severity', 'unknown')}] {alert.get('type', 'unknown')}")


def collect_command(config: Config) -> None:
    """Start metrics collection daemon."""
    print("=" * 60)
    print("AI Monitoring Platform - Collection Daemon")
    print("=" * 60)

    collector = MetricsCollector(config)
    collector.start()

    print("\nMetrics collector started.")
    print("Press Ctrl+C to stop.\n")

    try:
        while True:
            time.sleep(60)
            summary = collector.get_summary()
            stats = summary.get("collector", {}).get("stats", {})
            print(f"[{datetime.now()}] Requests: {stats.get('total_requests', 0)} | "
                  f"Flushes: {stats.get('successful_flushes', 0)} | "
                  f"Errors: {stats.get('failed_flushes', 0)}")
    except KeyboardInterrupt:
        print("\nShutting down...")
        collector.stop()
        print("Collection daemon stopped.")


def demo_command(config: Config) -> None:
    """Run demo with sample data."""
    print("=" * 60)
    print("AI Monitoring Platform - Demo Mode")
    print("=" * 60)

    collector = MetricsCollector(config)
    collector.start()

    providers = ["openai", "anthropic"]
    models = {
        "openai": ["gpt-4", "gpt-4-turbo", "gpt-3.5-turbo"],
        "anthropic": ["claude-3-opus", "claude-3-sonnet", "claude-3-haiku"],
    }
    teams = ["engineering", "product", "support", "research"]
    projects = ["chatbot", "summarization", "code-assistant", "data-analysis"]

    sample_prompts = [
        "What is the capital of France?",
        "Explain quantum computing in simple terms.",
        "Write a Python function to calculate fibonacci numbers.",
        "Summarize the following article...",
        "Help me debug this code...",
    ]

    sample_responses = [
        "The capital of France is Paris.",
        "Quantum computing uses quantum bits or qubits...",
        "def fibonacci(n): return n if n < 2 else fibonacci(n-1) + fibonacci(n-2)",
        "The article discusses the importance of...",
        "I found a bug in line 42 where...",
    ]

    print("\nGenerating sample metrics...")
    print("Press Ctrl+C to stop.\n")

    try:
        count = 0
        while True:
            # Generate random request
            provider = random.choice(providers)
            model = random.choice(models[provider])
            prompt_idx = random.randint(0, len(sample_prompts) - 1)

            request = AIRequest(
                request_id=str(uuid.uuid4()),
                provider=provider,
                model=model,
                prompt=sample_prompts[prompt_idx],
                response=sample_responses[prompt_idx],
                input_tokens=random.randint(10, 500),
                output_tokens=random.randint(50, 2000),
                latency_ms=random.uniform(100, 5000),
                status="success" if random.random() > 0.05 else "error",
                environment="production" if random.random() > 0.2 else "staging",
                team=random.choice(teams),
                project=random.choice(projects),
                user_id=f"user-{random.randint(1, 100)}",
            )

            collector.record(request)
            count += 1

            if count % 10 == 0:
                print(f"Generated {count} requests...")

            time.sleep(random.uniform(0.1, 1.0))

    except KeyboardInterrupt:
        print(f"\nStopping demo... Generated {count} requests.")
        collector.flush()
        collector.stop()

        # Show summary
        print("\n" + "=" * 60)
        print("Demo Summary")
        print("=" * 60)
        summary_command(config)


def interactive_command(config: Config) -> None:
    """Interactive mode."""
    print("=" * 60)
    print("AI Monitoring Platform - Interactive Mode")
    print("=" * 60)

    collector = MetricsCollector(config)
    alert_manager = AlertManager(config)

    while True:
        print("\n[Menu]")
        print("  1. Show status")
        print("  2. Show metrics summary")
        print("  3. Show active alerts")
        print("  4. Record sample request")
        print("  5. Flush metrics")
        print("  6. Run health check")
        print("  7. Check compliance")
        print("  8. Exit")

        try:
            choice = input("\nSelect option: ").strip()

            if choice == "1":
                status_command(config)
            elif choice == "2":
                summary_command(config)
            elif choice == "3":
                alerts_command(config)
            elif choice == "4":
                # Record sample request
                request = AIRequest(
                    request_id=str(uuid.uuid4()),
                    provider="openai",
                    model="gpt-4",
                    prompt="What is 2+2?",
                    response="2+2 equals 4.",
                    input_tokens=10,
                    output_tokens=15,
                    latency_ms=250.0,
                )
                results = collector.record(request)
                print("\nRecorded request:")
                print(f"  Request ID: {request.request_id}")
                print(f"  Quality Score: {results.get('cognitive', {}).quality.overall_score:.2f}")
                print(f"  Cost: ${results.get('finops', {}).cost.total_cost:.4f}")
            elif choice == "5":
                results = collector.flush()
                print("\nFlush results:")
                for category, result in results.items():
                    print(f"  {category}: {result.get('indexed', 0)} indexed, "
                          f"{result.get('errors', 0)} errors")
            elif choice == "6":
                metric = collector.record_health_check(status=HealthStatus.HEALTHY)
                print(f"\nHealth check recorded: {metric.health.status.value}")
            elif choice == "7":
                violations = collector.compliance_monitor.check_compliance_violations()
                print(f"\nCompliance violations: {len(violations)}")
                for v in violations:
                    print(f"  - [{v['severity']}] {v['type']}")
            elif choice == "8":
                print("Goodbye!")
                break
            else:
                print("Invalid option.")

        except KeyboardInterrupt:
            print("\n\nGoodbye!")
            break
        except Exception as e:
            print(f"Error: {e}")


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="AI Monitoring & Observability Platform",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Commands:
  setup         Set up Elasticsearch indices and templates
  status        Show monitoring status
  alerts        Show active alerts
  summary       Show metrics summary
  collect       Start metrics collection daemon
  demo          Run demo with sample data
  interactive   Interactive mode

Examples:
  python ai_monitoring.py setup
  python ai_monitoring.py status
  python ai_monitoring.py demo
        """
    )

    parser.add_argument(
        "command",
        choices=["setup", "status", "alerts", "summary", "collect", "demo", "interactive"],
        help="Command to run"
    )

    parser.add_argument(
        "-c", "--config",
        type=str,
        default=None,
        help="Path to configuration file"
    )

    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Enable verbose output"
    )

    args = parser.parse_args()

    # Set logging level
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    # Load configuration
    try:
        config = load_config(args.config)
    except Exception as e:
        print(f"Error loading configuration: {e}")
        sys.exit(1)

    # Execute command
    commands = {
        "setup": setup_command,
        "status": status_command,
        "alerts": alerts_command,
        "summary": summary_command,
        "collect": collect_command,
        "demo": demo_command,
        "interactive": interactive_command,
    }

    try:
        commands[args.command](config)
    except KeyboardInterrupt:
        print("\n\nInterrupted.")
        sys.exit(0)
    except Exception as e:
        logger.exception(f"Error executing command: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
