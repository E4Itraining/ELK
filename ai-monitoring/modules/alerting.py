"""
Alerting Module
===============

Provides alerting capabilities for AI monitoring including:
- Multiple notification channels (Slack, Email, Webhook, PagerDuty)
- Alert rules and thresholds
- Alert deduplication and cooldowns
- Alert escalation
"""

import json
import logging
import hashlib
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Optional, Any, Callable
from dataclasses import dataclass, field
from enum import Enum
from threading import Lock
import urllib.request
import urllib.error

from .config import Config, AlertingConfig

logger = logging.getLogger(__name__)


class AlertSeverity(Enum):
    """Alert severity levels."""
    INFO = "info"
    WARNING = "warning"
    CRITICAL = "critical"


class AlertStatus(Enum):
    """Alert status."""
    ACTIVE = "active"
    ACKNOWLEDGED = "acknowledged"
    RESOLVED = "resolved"
    SUPPRESSED = "suppressed"


class AlertCategory(Enum):
    """Alert category."""
    TECHNICAL = "technical"
    COGNITIVE = "cognitive"
    FINOPS = "finops"
    DEVOPS = "devops"
    COMPLIANCE = "compliance"


@dataclass
class Alert:
    """Represents an alert."""
    id: str
    name: str
    category: AlertCategory
    severity: AlertSeverity
    message: str
    details: Dict[str, Any] = field(default_factory=dict)
    status: AlertStatus = AlertStatus.ACTIVE
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    acknowledged_by: Optional[str] = None
    acknowledged_at: Optional[datetime] = None
    resolved_at: Optional[datetime] = None
    dedup_key: str = ""
    notification_sent: bool = False
    escalation_level: int = 0

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        result = {
            "id": self.id,
            "name": self.name,
            "category": self.category.value,
            "severity": self.severity.value,
            "message": self.message,
            "details": self.details,
            "status": self.status.value,
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat(),
            "dedup_key": self.dedup_key,
            "notification_sent": self.notification_sent,
            "escalation_level": self.escalation_level,
        }

        if self.acknowledged_by:
            result["acknowledged_by"] = self.acknowledged_by
        if self.acknowledged_at:
            result["acknowledged_at"] = self.acknowledged_at.isoformat()
        if self.resolved_at:
            result["resolved_at"] = self.resolved_at.isoformat()

        return result


@dataclass
class AlertRule:
    """Alert rule configuration."""
    name: str
    condition: str  # Expression to evaluate
    category: AlertCategory
    severity: AlertSeverity
    message_template: str
    cooldown_minutes: int = 15
    enabled: bool = True
    channels: List[str] = field(default_factory=lambda: ["slack", "email"])


class NotificationChannel:
    """Base class for notification channels."""

    def send(self, alert: Alert) -> bool:
        """Send alert notification."""
        raise NotImplementedError


class SlackNotificationChannel(NotificationChannel):
    """Slack notification channel."""

    def __init__(self, webhook_url: str, channels: Dict[str, str]):
        """
        Initialize Slack channel.

        Args:
            webhook_url: Slack webhook URL
            channels: Mapping of severity to channel name
        """
        self.webhook_url = webhook_url
        self.channels = channels

    def send(self, alert: Alert) -> bool:
        """Send alert to Slack."""
        if not self.webhook_url:
            logger.warning("Slack webhook URL not configured")
            return False

        # Determine channel
        channel = self.channels.get(
            alert.severity.value,
            self.channels.get("warning", "#ai-alerts")
        )

        # Build message
        color = {
            AlertSeverity.INFO: "#36a64f",
            AlertSeverity.WARNING: "#ffcc00",
            AlertSeverity.CRITICAL: "#ff0000",
        }.get(alert.severity, "#808080")

        payload = {
            "channel": channel,
            "attachments": [
                {
                    "color": color,
                    "title": f"[{alert.severity.value.upper()}] {alert.name}",
                    "text": alert.message,
                    "fields": [
                        {
                            "title": "Category",
                            "value": alert.category.value,
                            "short": True,
                        },
                        {
                            "title": "Status",
                            "value": alert.status.value,
                            "short": True,
                        },
                    ],
                    "footer": f"AI Monitoring Platform | Alert ID: {alert.id}",
                    "ts": int(alert.created_at.timestamp()),
                }
            ],
        }

        # Add details as fields
        for key, value in list(alert.details.items())[:5]:
            payload["attachments"][0]["fields"].append({
                "title": key.replace("_", " ").title(),
                "value": str(value),
                "short": True,
            })

        try:
            data = json.dumps(payload).encode('utf-8')
            req = urllib.request.Request(
                self.webhook_url,
                data=data,
                headers={'Content-Type': 'application/json'},
                method='POST'
            )
            with urllib.request.urlopen(req, timeout=10) as response:
                return response.status == 200

        except urllib.error.URLError as e:
            logger.error(f"Failed to send Slack notification: {e}")
            return False


class EmailNotificationChannel(NotificationChannel):
    """Email notification channel."""

    def __init__(
        self,
        smtp_host: str,
        smtp_port: int,
        from_address: str,
        recipients: Dict[str, List[str]],
        username: Optional[str] = None,
        password: Optional[str] = None
    ):
        """
        Initialize Email channel.

        Args:
            smtp_host: SMTP server host
            smtp_port: SMTP server port
            from_address: Sender email address
            recipients: Mapping of severity to recipient list
            username: SMTP username (optional)
            password: SMTP password (optional)
        """
        self.smtp_host = smtp_host
        self.smtp_port = smtp_port
        self.from_address = from_address
        self.recipients = recipients
        self.username = username
        self.password = password

    def send(self, alert: Alert) -> bool:
        """Send alert via email."""
        if not self.smtp_host or not self.from_address:
            logger.warning("Email not configured properly")
            return False

        # Get recipients for severity
        to_addresses = self.recipients.get(
            alert.severity.value,
            self.recipients.get("warning", [])
        )

        if not to_addresses:
            logger.warning(f"No email recipients for severity {alert.severity.value}")
            return False

        # Build email
        msg = MIMEMultipart('alternative')
        msg['Subject'] = f"[{alert.severity.value.upper()}] AI Alert: {alert.name}"
        msg['From'] = self.from_address
        msg['To'] = ", ".join(to_addresses)

        # Text version
        text_body = f"""
AI Monitoring Alert

Name: {alert.name}
Severity: {alert.severity.value.upper()}
Category: {alert.category.value}
Status: {alert.status.value}

Message:
{alert.message}

Details:
{json.dumps(alert.details, indent=2)}

Alert ID: {alert.id}
Created: {alert.created_at.isoformat()}

---
AI Monitoring Platform
        """.strip()

        # HTML version
        html_body = f"""
        <html>
        <head>
            <style>
                body {{ font-family: Arial, sans-serif; }}
                .alert-box {{ padding: 20px; border-radius: 5px; margin-bottom: 20px; }}
                .critical {{ background-color: #ffe6e6; border-left: 5px solid #ff0000; }}
                .warning {{ background-color: #fff9e6; border-left: 5px solid #ffcc00; }}
                .info {{ background-color: #e6ffe6; border-left: 5px solid #36a64f; }}
                .details {{ background-color: #f5f5f5; padding: 10px; border-radius: 3px; }}
                table {{ border-collapse: collapse; width: 100%; }}
                td, th {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
            </style>
        </head>
        <body>
            <h2>AI Monitoring Alert</h2>
            <div class="alert-box {alert.severity.value}">
                <h3>[{alert.severity.value.upper()}] {alert.name}</h3>
                <p>{alert.message}</p>
            </div>

            <table>
                <tr><th>Category</th><td>{alert.category.value}</td></tr>
                <tr><th>Status</th><td>{alert.status.value}</td></tr>
                <tr><th>Alert ID</th><td>{alert.id}</td></tr>
                <tr><th>Created</th><td>{alert.created_at.isoformat()}</td></tr>
            </table>

            <h4>Details</h4>
            <div class="details">
                <pre>{json.dumps(alert.details, indent=2)}</pre>
            </div>

            <hr>
            <p><small>AI Monitoring Platform</small></p>
        </body>
        </html>
        """

        msg.attach(MIMEText(text_body, 'plain'))
        msg.attach(MIMEText(html_body, 'html'))

        try:
            with smtplib.SMTP(self.smtp_host, self.smtp_port) as server:
                server.starttls()
                if self.username and self.password:
                    server.login(self.username, self.password)
                server.sendmail(self.from_address, to_addresses, msg.as_string())

            logger.info(f"Email alert sent to {len(to_addresses)} recipients")
            return True

        except Exception as e:
            logger.error(f"Failed to send email notification: {e}")
            return False


class WebhookNotificationChannel(NotificationChannel):
    """Generic webhook notification channel."""

    def __init__(self, url: str, headers: Optional[Dict[str, str]] = None):
        """
        Initialize Webhook channel.

        Args:
            url: Webhook URL
            headers: Custom headers
        """
        self.url = url
        self.headers = headers or {}

    def send(self, alert: Alert) -> bool:
        """Send alert to webhook."""
        if not self.url:
            return False

        payload = alert.to_dict()

        try:
            data = json.dumps(payload).encode('utf-8')
            headers = {'Content-Type': 'application/json'}
            headers.update(self.headers)

            req = urllib.request.Request(
                self.url,
                data=data,
                headers=headers,
                method='POST'
            )
            with urllib.request.urlopen(req, timeout=10) as response:
                return 200 <= response.status < 300

        except Exception as e:
            logger.error(f"Failed to send webhook notification: {e}")
            return False


class AlertManager:
    """
    Manages alerts and notifications for AI monitoring.

    Features:
    - Alert creation and management
    - Deduplication based on alert content
    - Cooldown periods to prevent alert fatigue
    - Multiple notification channels
    - Alert escalation
    """

    def __init__(self, config: Config):
        """
        Initialize the alert manager.

        Args:
            config: Configuration object
        """
        self.config = config
        self.alerting_config = config.alerting
        self._alerts: Dict[str, Alert] = {}
        self._alert_history: List[Alert] = []
        self._cooldowns: Dict[str, datetime] = {}
        self._lock = Lock()

        # Initialize channels
        self._channels: Dict[str, NotificationChannel] = {}
        self._init_channels()

        # Alert counter for IDs
        self._alert_counter = 0

    def _init_channels(self) -> None:
        """Initialize notification channels from config."""
        alert_config = self.alerting_config

        # Slack
        if alert_config.slack.enabled and alert_config.slack.webhook_url:
            self._channels["slack"] = SlackNotificationChannel(
                webhook_url=alert_config.slack.webhook_url,
                channels=alert_config.slack.channels
            )

        # Email
        if alert_config.email.enabled:
            self._channels["email"] = EmailNotificationChannel(
                smtp_host=alert_config.email.smtp_host,
                smtp_port=alert_config.email.smtp_port,
                from_address=alert_config.email.from_address,
                recipients=alert_config.email.recipients,
            )

    def add_channel(self, name: str, channel: NotificationChannel) -> None:
        """Add a notification channel."""
        self._channels[name] = channel

    def _generate_alert_id(self) -> str:
        """Generate a unique alert ID."""
        self._alert_counter += 1
        return f"ALT-{datetime.now(timezone.utc).strftime('%Y%m%d')}-{self._alert_counter:05d}"

    def _generate_dedup_key(self, name: str, category: AlertCategory, details: Dict) -> str:
        """Generate a deduplication key."""
        content = f"{name}:{category.value}:{json.dumps(details, sort_keys=True)}"
        return hashlib.md5(content.encode()).hexdigest()[:16]

    def _is_in_cooldown(self, dedup_key: str, cooldown_minutes: int) -> bool:
        """Check if an alert is in cooldown period."""
        if dedup_key not in self._cooldowns:
            return False

        cooldown_end = self._cooldowns[dedup_key]
        return datetime.now(timezone.utc) < cooldown_end

    def create_alert(
        self,
        name: str,
        category: AlertCategory,
        severity: AlertSeverity,
        message: str,
        details: Optional[Dict[str, Any]] = None,
        cooldown_minutes: int = 15,
        channels: Optional[List[str]] = None
    ) -> Optional[Alert]:
        """
        Create a new alert.

        Args:
            name: Alert name
            category: Alert category
            severity: Alert severity
            message: Alert message
            details: Additional details
            cooldown_minutes: Cooldown period
            channels: Notification channels to use

        Returns:
            Created alert or None if deduplicated
        """
        if not self.alerting_config.enabled:
            return None

        details = details or {}
        channels = channels or ["slack", "email"]

        dedup_key = self._generate_dedup_key(name, category, details)

        with self._lock:
            # Check cooldown
            if self._is_in_cooldown(dedup_key, cooldown_minutes):
                logger.debug(f"Alert {name} is in cooldown, skipping")
                return None

            # Check for existing active alert
            if dedup_key in self._alerts:
                existing = self._alerts[dedup_key]
                if existing.status == AlertStatus.ACTIVE:
                    existing.updated_at = datetime.now(timezone.utc)
                    return existing

            # Create new alert
            alert = Alert(
                id=self._generate_alert_id(),
                name=name,
                category=category,
                severity=severity,
                message=message,
                details=details,
                dedup_key=dedup_key,
            )

            self._alerts[dedup_key] = alert
            self._alert_history.append(alert)

            # Set cooldown
            self._cooldowns[dedup_key] = (
                datetime.now(timezone.utc) + timedelta(minutes=cooldown_minutes)
            )

        # Send notifications
        self._send_notifications(alert, channels)

        logger.info(f"Created alert: {alert.id} - {name}")
        return alert

    def _send_notifications(self, alert: Alert, channel_names: List[str]) -> None:
        """Send notifications through specified channels."""
        for channel_name in channel_names:
            if channel_name in self._channels:
                try:
                    success = self._channels[channel_name].send(alert)
                    if success:
                        alert.notification_sent = True
                except Exception as e:
                    logger.error(f"Failed to send notification via {channel_name}: {e}")

    def acknowledge_alert(self, alert_id: str, acknowledged_by: str) -> Optional[Alert]:
        """
        Acknowledge an alert.

        Args:
            alert_id: Alert ID
            acknowledged_by: User who acknowledged

        Returns:
            Updated alert or None if not found
        """
        with self._lock:
            for alert in self._alerts.values():
                if alert.id == alert_id:
                    alert.status = AlertStatus.ACKNOWLEDGED
                    alert.acknowledged_by = acknowledged_by
                    alert.acknowledged_at = datetime.now(timezone.utc)
                    alert.updated_at = datetime.now(timezone.utc)
                    logger.info(f"Alert {alert_id} acknowledged by {acknowledged_by}")
                    return alert
        return None

    def resolve_alert(self, alert_id: str) -> Optional[Alert]:
        """
        Resolve an alert.

        Args:
            alert_id: Alert ID

        Returns:
            Updated alert or None if not found
        """
        with self._lock:
            for dedup_key, alert in list(self._alerts.items()):
                if alert.id == alert_id:
                    alert.status = AlertStatus.RESOLVED
                    alert.resolved_at = datetime.now(timezone.utc)
                    alert.updated_at = datetime.now(timezone.utc)
                    del self._alerts[dedup_key]
                    logger.info(f"Alert {alert_id} resolved")
                    return alert
        return None

    def get_active_alerts(
        self,
        category: Optional[AlertCategory] = None,
        severity: Optional[AlertSeverity] = None
    ) -> List[Alert]:
        """
        Get active alerts with optional filters.

        Args:
            category: Filter by category
            severity: Filter by severity

        Returns:
            List of active alerts
        """
        with self._lock:
            alerts = [
                a for a in self._alerts.values()
                if a.status == AlertStatus.ACTIVE
            ]

            if category:
                alerts = [a for a in alerts if a.category == category]

            if severity:
                alerts = [a for a in alerts if a.severity == severity]

            return alerts

    def get_alert_history(
        self,
        limit: int = 100,
        category: Optional[AlertCategory] = None
    ) -> List[Alert]:
        """
        Get alert history.

        Args:
            limit: Maximum number of alerts to return
            category: Filter by category

        Returns:
            List of historical alerts
        """
        with self._lock:
            alerts = self._alert_history.copy()

            if category:
                alerts = [a for a in alerts if a.category == category]

            return alerts[-limit:]

    def get_alert_summary(self) -> Dict[str, Any]:
        """Get alert summary statistics."""
        with self._lock:
            active_alerts = [a for a in self._alerts.values() if a.status == AlertStatus.ACTIVE]

            return {
                "total_active": len(active_alerts),
                "by_severity": {
                    "critical": sum(1 for a in active_alerts if a.severity == AlertSeverity.CRITICAL),
                    "warning": sum(1 for a in active_alerts if a.severity == AlertSeverity.WARNING),
                    "info": sum(1 for a in active_alerts if a.severity == AlertSeverity.INFO),
                },
                "by_category": {
                    cat.value: sum(1 for a in active_alerts if a.category == cat)
                    for cat in AlertCategory
                },
                "total_historical": len(self._alert_history),
            }

    def process_monitoring_alerts(
        self,
        technical_violations: List[Dict],
        finops_alerts: List[Dict],
        compliance_violations: List[Dict]
    ) -> List[Alert]:
        """
        Process alerts from monitoring modules.

        Args:
            technical_violations: Technical threshold violations
            finops_alerts: FinOps budget alerts
            compliance_violations: Compliance violations

        Returns:
            List of created alerts
        """
        created_alerts = []

        # Process technical violations
        for v in technical_violations:
            severity = AlertSeverity.CRITICAL if v["severity"] == "critical" else AlertSeverity.WARNING
            alert = self.create_alert(
                name=f"Technical: {v['type'].replace('_', ' ').title()}",
                category=AlertCategory.TECHNICAL,
                severity=severity,
                message=f"Threshold exceeded: {v['value']:.2f} > {v['threshold']:.2f}",
                details=v,
            )
            if alert:
                created_alerts.append(alert)

        # Process FinOps alerts
        for a in finops_alerts:
            alert = self.create_alert(
                name=f"FinOps: {a['type'].replace('_', ' ').title()}",
                category=AlertCategory.FINOPS,
                severity=AlertSeverity.CRITICAL if a.get("severity") == "critical" else AlertSeverity.WARNING,
                message=a.get("message", "Budget threshold reached"),
                details=a,
            )
            if alert:
                created_alerts.append(alert)

        # Process compliance violations
        for v in compliance_violations:
            alert = self.create_alert(
                name=f"Compliance: {v['type'].replace('_', ' ').title()}",
                category=AlertCategory.COMPLIANCE,
                severity=AlertSeverity.CRITICAL if v["severity"] == "high" else AlertSeverity.WARNING,
                message=f"Compliance violation detected: {v['type']}",
                details=v,
            )
            if alert:
                created_alerts.append(alert)

        return created_alerts

    def clear_cooldowns(self) -> None:
        """Clear all cooldowns (for testing)."""
        with self._lock:
            self._cooldowns.clear()

    def clear_alerts(self) -> None:
        """Clear all alerts (for testing)."""
        with self._lock:
            self._alerts.clear()
            self._alert_history.clear()
