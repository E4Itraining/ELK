"""
Report Generator Module for ELK Upgrade Audit Tool
===================================================
Generates audit and validation reports in various formats.
"""

import json
import logging
from typing import Dict, Any, Optional
from datetime import datetime
from pathlib import Path


class ReportGenerator:
    """
    Generates reports from audit and validation results.
    Supports HTML, JSON, and Markdown formats.
    """

    def __init__(self, output_dir: str = "./reports"):
        """
        Initialize the report generator.

        Args:
            output_dir: Directory to save reports.
        """
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.logger = logging.getLogger(__name__)

    def generate_pre_upgrade_report(self, audit_report, compatibility_result=None,
                                    backup_status=None, format: str = "html") -> str:
        """
        Generate a pre-upgrade audit report.

        Args:
            audit_report: AuditReport from PreUpgradeAudit
            compatibility_result: CompatibilityResult from CompatibilityChecker
            backup_status: Backup readiness status
            format: Output format (html, json, markdown)

        Returns:
            Path to the generated report.
        """
        timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
        filename = f"pre-upgrade-audit-{timestamp}"

        if format == "html":
            return self._generate_pre_upgrade_html(
                audit_report, compatibility_result, backup_status, filename
            )
        elif format == "json":
            return self._generate_pre_upgrade_json(
                audit_report, compatibility_result, backup_status, filename
            )
        else:
            return self._generate_pre_upgrade_markdown(
                audit_report, compatibility_result, backup_status, filename
            )

    def generate_post_upgrade_report(self, validation_report, format: str = "html") -> str:
        """
        Generate a post-upgrade validation report.

        Args:
            validation_report: ValidationReport from PostUpgradeValidator
            format: Output format (html, json, markdown)

        Returns:
            Path to the generated report.
        """
        timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
        filename = f"post-upgrade-validation-{timestamp}"

        if format == "html":
            return self._generate_post_upgrade_html(validation_report, filename)
        elif format == "json":
            return self._generate_post_upgrade_json(validation_report, filename)
        else:
            return self._generate_post_upgrade_markdown(validation_report, filename)

    def _generate_pre_upgrade_html(self, audit_report, compatibility_result,
                                   backup_status, filename: str) -> str:
        """Generate HTML pre-upgrade report."""
        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>ELK Pre-Upgrade Audit Report</title>
    <style>
        :root {{
            --primary: #005571;
            --success: #00bfb3;
            --warning: #fec514;
            --danger: #bd271e;
            --gray: #69707d;
        }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, sans-serif;
            line-height: 1.6;
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
            background: #f5f7fa;
            color: #343741;
        }}
        .header {{
            background: linear-gradient(135deg, var(--primary), #00a9e5);
            color: white;
            padding: 30px;
            border-radius: 8px;
            margin-bottom: 20px;
        }}
        .header h1 {{ margin: 0; }}
        .header .meta {{ opacity: 0.9; margin-top: 10px; }}
        .summary {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-bottom: 20px;
        }}
        .summary-card {{
            background: white;
            padding: 20px;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
            text-align: center;
        }}
        .summary-card.ready {{ border-left: 4px solid var(--success); }}
        .summary-card.not-ready {{ border-left: 4px solid var(--danger); }}
        .summary-card h2 {{ margin: 0 0 10px 0; font-size: 2em; }}
        .card {{
            background: white;
            padding: 20px;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
            margin-bottom: 20px;
        }}
        .card h3 {{
            margin-top: 0;
            border-bottom: 2px solid #eee;
            padding-bottom: 10px;
        }}
        .check {{
            padding: 12px;
            margin: 8px 0;
            border-radius: 4px;
            display: flex;
            align-items: flex-start;
        }}
        .check.passed {{ background: #e6f9f7; border-left: 4px solid var(--success); }}
        .check.warning {{ background: #fef6e6; border-left: 4px solid var(--warning); }}
        .check.failed {{ background: #fce8e6; border-left: 4px solid var(--danger); }}
        .check.error {{ background: #fce8e6; border-left: 4px solid var(--danger); }}
        .check-icon {{
            width: 24px;
            height: 24px;
            margin-right: 12px;
            flex-shrink: 0;
        }}
        .check-content {{ flex-grow: 1; }}
        .check-name {{ font-weight: bold; }}
        .check-message {{ color: var(--gray); margin-top: 4px; }}
        .recommendations {{
            margin-top: 8px;
            padding-left: 20px;
            font-size: 0.9em;
            color: #666;
        }}
        .recommendations li {{ margin: 4px 0; }}
        .badge {{
            display: inline-block;
            padding: 2px 8px;
            border-radius: 4px;
            font-size: 0.8em;
            font-weight: bold;
            text-transform: uppercase;
        }}
        .badge.passed {{ background: var(--success); color: white; }}
        .badge.warning {{ background: var(--warning); color: #333; }}
        .badge.failed {{ background: var(--danger); color: white; }}
        .upgrade-path {{
            display: flex;
            align-items: center;
            flex-wrap: wrap;
            gap: 8px;
            padding: 15px;
            background: #f0f4f8;
            border-radius: 4px;
            margin: 10px 0;
        }}
        .version-box {{
            background: var(--primary);
            color: white;
            padding: 8px 16px;
            border-radius: 4px;
            font-weight: bold;
        }}
        .arrow {{ color: var(--primary); font-size: 1.5em; }}
        table {{
            width: 100%;
            border-collapse: collapse;
            margin: 10px 0;
        }}
        th, td {{
            text-align: left;
            padding: 10px;
            border-bottom: 1px solid #eee;
        }}
        th {{ background: #f0f4f8; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>ELK Pre-Upgrade Audit Report</h1>
        <div class="meta">
            <strong>Cluster:</strong> {audit_report.cluster_name} |
            <strong>Current Version:</strong> {audit_report.current_version} |
            <strong>Target Version:</strong> {audit_report.target_version} |
            <strong>Generated:</strong> {audit_report.timestamp}
        </div>
    </div>

    <div class="summary">
        <div class="summary-card {'ready' if audit_report.ready_for_upgrade else 'not-ready'}">
            <h2>{'READY' if audit_report.ready_for_upgrade else 'NOT READY'}</h2>
            <p>For Upgrade</p>
        </div>
        <div class="summary-card">
            <h2 style="color: var(--success)">{audit_report.summary.get('passed', 0)}</h2>
            <p>Passed</p>
        </div>
        <div class="summary-card">
            <h2 style="color: var(--warning)">{audit_report.summary.get('warning', 0)}</h2>
            <p>Warnings</p>
        </div>
        <div class="summary-card">
            <h2 style="color: var(--danger)">{audit_report.summary.get('failed', 0)}</h2>
            <p>Failed</p>
        </div>
    </div>
"""

        # Add compatibility section if available
        if compatibility_result:
            html += f"""
    <div class="card">
        <h3>Upgrade Compatibility</h3>
        <p><strong>Compatible:</strong> <span class="badge {'passed' if compatibility_result.compatible else 'failed'}">
            {'Yes' if compatibility_result.compatible else 'No'}</span></p>
        <p><strong>Upgrade Type:</strong> {compatibility_result.upgrade_type.value}</p>

        <h4>Upgrade Path</h4>
        <div class="upgrade-path">
            {'<span class="arrow">→</span>'.join([f'<span class="version-box">{v}</span>' for v in compatibility_result.upgrade_path])}
        </div>
"""

            if compatibility_result.blockers:
                html += """
        <h4>Blockers</h4>
        <ul style="color: var(--danger);">
"""
                for blocker in compatibility_result.blockers:
                    html += f"            <li>{blocker}</li>\n"
                html += "        </ul>\n"

            if compatibility_result.breaking_changes:
                html += """
        <h4>Breaking Changes</h4>
        <table>
            <tr><th>Category</th><th>Change</th><th>Action Required</th><th>Severity</th></tr>
"""
                for change in compatibility_result.breaking_changes:
                    html += f"""            <tr>
                <td>{change.get('category', '')}</td>
                <td>{change.get('change', '')}</td>
                <td>{change.get('action', '')}</td>
                <td><span class="badge {'failed' if change.get('severity') == 'critical' else 'warning'}">{change.get('severity', '')}</span></td>
            </tr>
"""
                html += "        </table>\n"

            html += "    </div>\n"

        # Group checks by category
        categories = {}
        for check in audit_report.checks:
            cat = check.category
            if cat not in categories:
                categories[cat] = []
            categories[cat].append(check)

        for category, checks in categories.items():
            html += f"""
    <div class="card">
        <h3>{category.title()} Checks</h3>
"""
            for check in checks:
                status_class = check.status.value
                html += f"""
        <div class="check {status_class}">
            <div class="check-content">
                <div class="check-name">{check.name}</div>
                <div class="check-message">{check.message}</div>
"""
                if check.recommendations:
                    html += """                <ul class="recommendations">
"""
                    for rec in check.recommendations:
                        html += f"                    <li>{rec}</li>\n"
                    html += "                </ul>\n"
                html += """            </div>
        </div>
"""
            html += "    </div>\n"

        html += """
</body>
</html>
"""

        filepath = self.output_dir / f"{filename}.html"
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(html)

        self.logger.info(f"Generated HTML report: {filepath}")
        return str(filepath)

    def _generate_pre_upgrade_json(self, audit_report, compatibility_result,
                                   backup_status, filename: str) -> str:
        """Generate JSON pre-upgrade report."""
        data = {
            "report_type": "pre-upgrade-audit",
            "generated_at": datetime.now().isoformat(),
            "cluster": {
                "name": audit_report.cluster_name,
                "current_version": audit_report.current_version,
                "target_version": audit_report.target_version
            },
            "ready_for_upgrade": audit_report.ready_for_upgrade,
            "summary": audit_report.summary,
            "checks": [
                {
                    "name": c.name,
                    "category": c.category,
                    "status": c.status.value,
                    "message": c.message,
                    "severity": c.severity,
                    "details": c.details,
                    "recommendations": c.recommendations
                }
                for c in audit_report.checks
            ]
        }

        if compatibility_result:
            data["compatibility"] = {
                "compatible": compatibility_result.compatible,
                "upgrade_type": compatibility_result.upgrade_type.value,
                "upgrade_path": compatibility_result.upgrade_path,
                "warnings": compatibility_result.warnings,
                "blockers": compatibility_result.blockers,
                "breaking_changes": compatibility_result.breaking_changes
            }

        if backup_status:
            data["backup_status"] = backup_status

        filepath = self.output_dir / f"{filename}.json"
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2, default=str)

        self.logger.info(f"Generated JSON report: {filepath}")
        return str(filepath)

    def _generate_pre_upgrade_markdown(self, audit_report, compatibility_result,
                                       backup_status, filename: str) -> str:
        """Generate Markdown pre-upgrade report."""
        md = f"""# ELK Pre-Upgrade Audit Report

**Cluster:** {audit_report.cluster_name}
**Current Version:** {audit_report.current_version}
**Target Version:** {audit_report.target_version}
**Generated:** {audit_report.timestamp}

## Summary

| Status | Count |
|--------|-------|
| Passed | {audit_report.summary.get('passed', 0)} |
| Warning | {audit_report.summary.get('warning', 0)} |
| Failed | {audit_report.summary.get('failed', 0)} |

**Ready for Upgrade:** {'Yes' if audit_report.ready_for_upgrade else 'No'}

"""

        if compatibility_result:
            md += f"""## Upgrade Compatibility

**Compatible:** {'Yes' if compatibility_result.compatible else 'No'}
**Upgrade Type:** {compatibility_result.upgrade_type.value}
**Upgrade Path:** {' → '.join(compatibility_result.upgrade_path)}

"""
            if compatibility_result.blockers:
                md += "### Blockers\n\n"
                for blocker in compatibility_result.blockers:
                    md += f"- {blocker}\n"
                md += "\n"

            if compatibility_result.breaking_changes:
                md += "### Breaking Changes\n\n"
                md += "| Category | Change | Action | Severity |\n"
                md += "|----------|--------|--------|----------|\n"
                for change in compatibility_result.breaking_changes:
                    md += f"| {change.get('category', '')} | {change.get('change', '')} | {change.get('action', '')} | {change.get('severity', '')} |\n"
                md += "\n"

        # Group checks by category
        categories = {}
        for check in audit_report.checks:
            cat = check.category
            if cat not in categories:
                categories[cat] = []
            categories[cat].append(check)

        md += "## Audit Checks\n\n"

        for category, checks in categories.items():
            md += f"### {category.title()}\n\n"
            for check in checks:
                status_icon = {"passed": "✅", "warning": "⚠️", "failed": "❌", "error": "❌"}.get(check.status.value, "❓")
                md += f"**{status_icon} {check.name}**\n\n"
                md += f"{check.message}\n\n"
                if check.recommendations:
                    md += "Recommendations:\n"
                    for rec in check.recommendations:
                        md += f"- {rec}\n"
                    md += "\n"

        filepath = self.output_dir / f"{filename}.md"
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(md)

        self.logger.info(f"Generated Markdown report: {filepath}")
        return str(filepath)

    def _generate_post_upgrade_html(self, validation_report, filename: str) -> str:
        """Generate HTML post-upgrade report."""
        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>ELK Post-Upgrade Validation Report</title>
    <style>
        :root {{
            --primary: #005571;
            --success: #00bfb3;
            --warning: #fec514;
            --danger: #bd271e;
            --gray: #69707d;
        }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            line-height: 1.6;
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
            background: #f5f7fa;
            color: #343741;
        }}
        .header {{
            background: linear-gradient(135deg, {'var(--success)' if validation_report.passed else 'var(--danger)'}, {'#00d4c7' if validation_report.passed else '#ff6b6b'});
            color: white;
            padding: 30px;
            border-radius: 8px;
            margin-bottom: 20px;
        }}
        .header h1 {{ margin: 0; }}
        .summary {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
            gap: 15px;
            margin-bottom: 20px;
        }}
        .summary-card {{
            background: white;
            padding: 15px;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
            text-align: center;
        }}
        .summary-card h2 {{ margin: 0; font-size: 1.8em; }}
        .card {{
            background: white;
            padding: 20px;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
            margin-bottom: 20px;
        }}
        .check {{
            padding: 10px;
            margin: 8px 0;
            border-radius: 4px;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }}
        .check.passed {{ background: #e6f9f7; }}
        .check.warning {{ background: #fef6e6; }}
        .check.failed {{ background: #fce8e6; }}
        .badge {{
            padding: 4px 12px;
            border-radius: 4px;
            font-size: 0.8em;
            font-weight: bold;
        }}
        .badge.passed {{ background: var(--success); color: white; }}
        .badge.warning {{ background: var(--warning); color: #333; }}
        .badge.failed {{ background: var(--danger); color: white; }}
        .badge.skipped {{ background: var(--gray); color: white; }}
        .duration {{ color: var(--gray); font-size: 0.9em; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>{'✅ Validation Passed' if validation_report.passed else '❌ Validation Failed'}</h1>
        <p><strong>Cluster:</strong> {validation_report.cluster_name} |
           <strong>Version:</strong> {validation_report.version} |
           <strong>Duration:</strong> {validation_report.total_duration_ms}ms</p>
    </div>

    <div class="summary">
        <div class="summary-card">
            <h2 style="color: var(--success)">{validation_report.summary.get('passed', 0)}</h2>
            <p>Passed</p>
        </div>
        <div class="summary-card">
            <h2 style="color: var(--warning)">{validation_report.summary.get('warning', 0)}</h2>
            <p>Warnings</p>
        </div>
        <div class="summary-card">
            <h2 style="color: var(--danger)">{validation_report.summary.get('failed', 0)}</h2>
            <p>Failed</p>
        </div>
        <div class="summary-card">
            <h2 style="color: var(--gray)">{validation_report.summary.get('skipped', 0)}</h2>
            <p>Skipped</p>
        </div>
    </div>

    <div class="card">
        <h3>Validation Checks</h3>
"""

        for check in validation_report.checks:
            status = check.status.value
            html += f"""
        <div class="check {status}">
            <div>
                <strong>{check.name}</strong>
                <span class="duration">({check.duration_ms}ms)</span>
                <br><small>{check.message}</small>
            </div>
            <span class="badge {status}">{status.upper()}</span>
        </div>
"""

        html += """
    </div>
</body>
</html>
"""

        filepath = self.output_dir / f"{filename}.html"
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(html)

        self.logger.info(f"Generated HTML report: {filepath}")
        return str(filepath)

    def _generate_post_upgrade_json(self, validation_report, filename: str) -> str:
        """Generate JSON post-upgrade report."""
        data = {
            "report_type": "post-upgrade-validation",
            "timestamp": validation_report.timestamp,
            "cluster_name": validation_report.cluster_name,
            "version": validation_report.version,
            "passed": validation_report.passed,
            "summary": validation_report.summary,
            "total_duration_ms": validation_report.total_duration_ms,
            "checks": [
                {
                    "name": c.name,
                    "category": c.category,
                    "status": c.status.value,
                    "message": c.message,
                    "details": c.details,
                    "duration_ms": c.duration_ms
                }
                for c in validation_report.checks
            ]
        }

        filepath = self.output_dir / f"{filename}.json"
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2, default=str)

        self.logger.info(f"Generated JSON report: {filepath}")
        return str(filepath)

    def _generate_post_upgrade_markdown(self, validation_report, filename: str) -> str:
        """Generate Markdown post-upgrade report."""
        status_icon = "✅" if validation_report.passed else "❌"

        md = f"""# ELK Post-Upgrade Validation Report {status_icon}

**Cluster:** {validation_report.cluster_name}
**Version:** {validation_report.version}
**Timestamp:** {validation_report.timestamp}
**Duration:** {validation_report.total_duration_ms}ms

## Summary

| Status | Count |
|--------|-------|
| Passed | {validation_report.summary.get('passed', 0)} |
| Warning | {validation_report.summary.get('warning', 0)} |
| Failed | {validation_report.summary.get('failed', 0)} |
| Skipped | {validation_report.summary.get('skipped', 0)} |

## Validation Checks

| Check | Status | Duration | Message |
|-------|--------|----------|---------|
"""

        for check in validation_report.checks:
            status_icon = {"passed": "✅", "warning": "⚠️", "failed": "❌", "skipped": "⏭️"}.get(check.status.value, "❓")
            md += f"| {check.name} | {status_icon} {check.status.value} | {check.duration_ms}ms | {check.message} |\n"

        filepath = self.output_dir / f"{filename}.md"
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(md)

        self.logger.info(f"Generated Markdown report: {filepath}")
        return str(filepath)
