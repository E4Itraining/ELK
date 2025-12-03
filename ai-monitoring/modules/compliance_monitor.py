"""
Compliance Monitoring Module
============================

Monitors compliance aspects of AI systems including:
- GDPR compliance (consent, data retention, PII)
- Audit logging
- Data classification
- Model governance
- EU AI Act compliance
- Content policy enforcement
- Data lineage tracking
"""

import hashlib
import logging
import re
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Optional, Any, Set
from dataclasses import dataclass, field
from enum import Enum
from threading import Lock

from .config import Config, ComplianceConfig

logger = logging.getLogger(__name__)


class ComplianceEventType(Enum):
    """Compliance event types."""
    AUDIT = "audit"
    DATA_ACCESS = "data_access"
    PII_DETECTION = "pii_detection"
    CONSENT = "consent"
    DATA_DELETION = "data_deletion"
    POLICY_VIOLATION = "policy_violation"
    MODEL_APPROVAL = "model_approval"
    GOVERNANCE = "governance"


class AuditAction(Enum):
    """Audit action types."""
    CREATE = "create"
    READ = "read"
    UPDATE = "update"
    DELETE = "delete"
    EXECUTE = "execute"
    EXPORT = "export"
    SHARE = "share"


class AuditOutcome(Enum):
    """Audit outcome."""
    SUCCESS = "success"
    FAILURE = "failure"
    DENIED = "denied"
    ERROR = "error"


class ActorType(Enum):
    """Actor type."""
    USER = "user"
    SERVICE = "service"
    SYSTEM = "system"
    API_KEY = "api_key"


class ProcessingBasis(Enum):
    """GDPR processing basis."""
    CONSENT = "consent"
    CONTRACT = "contract"
    LEGAL_OBLIGATION = "legal_obligation"
    VITAL_INTERESTS = "vital_interests"
    PUBLIC_INTEREST = "public_interest"
    LEGITIMATE_INTEREST = "legitimate_interest"


class DataClassificationLevel(Enum):
    """Data classification levels."""
    PUBLIC = "public"
    INTERNAL = "internal"
    CONFIDENTIAL = "confidential"
    RESTRICTED = "restricted"


class PIIType(Enum):
    """Types of PII."""
    NAME = "name"
    EMAIL = "email"
    PHONE = "phone"
    ADDRESS = "address"
    SSN = "ssn"
    CREDIT_CARD = "credit_card"
    DATE_OF_BIRTH = "date_of_birth"
    IP_ADDRESS = "ip_address"
    BIOMETRIC = "biometric"
    HEALTH = "health"
    FINANCIAL = "financial"


class RedactionMethod(Enum):
    """PII redaction methods."""
    MASK = "mask"
    HASH = "hash"
    TOKENIZE = "tokenize"
    REMOVE = "remove"
    ENCRYPT = "encrypt"


class ModelApprovalStatus(Enum):
    """Model approval status."""
    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"
    SUSPENDED = "suspended"
    DEPRECATED = "deprecated"


class RiskLevel(Enum):
    """Risk level classification."""
    MINIMAL = "minimal"
    LIMITED = "limited"
    HIGH = "high"
    UNACCEPTABLE = "unacceptable"


class AIActRiskCategory(Enum):
    """EU AI Act risk categories."""
    MINIMAL = "minimal"
    LIMITED = "limited"
    HIGH = "high"
    UNACCEPTABLE = "unacceptable"


class ContentPolicyAction(Enum):
    """Content policy action."""
    ALLOWED = "allowed"
    FLAGGED = "flagged"
    BLOCKED = "blocked"
    REVIEW_REQUIRED = "review_required"


@dataclass
class AuditInfo:
    """Audit information."""
    action: AuditAction = AuditAction.READ
    resource_type: str = ""
    resource_id: str = ""
    outcome: AuditOutcome = AuditOutcome.SUCCESS
    reason: str = ""
    changes: List[Dict[str, str]] = field(default_factory=list)


@dataclass
class ActorInfo:
    """Actor information (who performed the action)."""
    type: ActorType = ActorType.USER
    id: str = ""
    name: str = ""
    email_hash: str = ""  # Hashed for privacy
    role: str = ""
    department: str = ""
    api_key_id: str = ""
    service_account: bool = False


@dataclass
class AccessInfo:
    """Access information."""
    ip_address_hash: str = ""  # Hashed for privacy
    country: str = ""
    region: str = ""
    city: str = ""
    user_agent: str = ""
    device_type: str = ""
    authentication_method: str = ""
    mfa_used: bool = False
    session_id: str = ""
    session_duration_seconds: int = 0


@dataclass
class ConsentInfo:
    """Consent information."""
    given: bool = False
    timestamp: Optional[datetime] = None
    version: str = ""
    purposes: List[str] = field(default_factory=list)
    withdrawable: bool = True


@dataclass
class GDPRInfo:
    """GDPR compliance information."""
    data_subject_id_hash: str = ""
    processing_basis: ProcessingBasis = ProcessingBasis.CONSENT
    consent: ConsentInfo = field(default_factory=ConsentInfo)
    data_categories: List[str] = field(default_factory=list)
    special_categories: bool = False
    retention_period_days: int = 90
    deletion_scheduled: Optional[datetime] = None
    cross_border_transfer: bool = False
    transfer_mechanism: str = ""
    dpia_required: bool = False
    dpia_reference: str = ""


@dataclass
class PIIInfo:
    """PII detection information."""
    detected: bool = False
    types: List[PIIType] = field(default_factory=list)
    count: int = 0
    redacted: bool = False
    redaction_method: RedactionMethod = RedactionMethod.MASK
    detection_confidence: float = 0.0


@dataclass
class DataClassificationInfo:
    """Data classification information."""
    level: DataClassificationLevel = DataClassificationLevel.INTERNAL
    categories: List[str] = field(default_factory=list)
    handling_instructions: List[str] = field(default_factory=list)
    encryption_required: bool = False
    encrypted: bool = False
    encryption_algorithm: str = ""


@dataclass
class ModelGovernanceInfo:
    """Model governance information."""
    model_id: str = ""
    model_version: str = ""
    model_name: str = ""
    provider: str = ""
    approval_status: ModelApprovalStatus = ModelApprovalStatus.PENDING
    approved_by: str = ""
    approved_at: Optional[datetime] = None
    risk_level: RiskLevel = RiskLevel.LIMITED
    risk_assessment_id: str = ""
    use_case_approved: List[str] = field(default_factory=list)
    restrictions: List[str] = field(default_factory=list)
    documentation_url: str = ""


@dataclass
class AIActInfo:
    """EU AI Act compliance information."""
    risk_category: AIActRiskCategory = AIActRiskCategory.LIMITED
    transparency_obligations_met: bool = True
    human_oversight_required: bool = False
    human_oversight_present: bool = False
    technical_documentation: bool = False
    conformity_assessment: str = ""


@dataclass
class ContentPolicyInfo:
    """Content policy information."""
    policy_version: str = ""
    violation_detected: bool = False
    violation_type: str = ""
    action_taken: ContentPolicyAction = ContentPolicyAction.ALLOWED
    review_required: bool = False
    reviewed_by: str = ""
    reviewed_at: Optional[datetime] = None


@dataclass
class DataLineageInfo:
    """Data lineage information."""
    source_systems: List[str] = field(default_factory=list)
    processing_steps: List[str] = field(default_factory=list)
    transformations: List[str] = field(default_factory=list)
    output_destinations: List[str] = field(default_factory=list)


@dataclass
class RetentionInfo:
    """Data retention information."""
    policy_name: str = ""
    retention_days: int = 90
    deletion_date: Optional[datetime] = None
    legal_hold: bool = False
    legal_hold_reason: str = ""


@dataclass
class RequestResponseInfo:
    """Request/response audit information."""
    prompt_hash: str = ""
    prompt_length: int = 0
    response_hash: str = ""
    response_length: int = 0
    stored: bool = False
    storage_location: str = ""


@dataclass
class ComplianceMetric:
    """Complete compliance metric."""
    event_type: ComplianceEventType = ComplianceEventType.AUDIT
    request_id: str = ""
    trace_id: str = ""
    environment: str = "production"
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    audit: AuditInfo = field(default_factory=AuditInfo)
    actor: ActorInfo = field(default_factory=ActorInfo)
    access: AccessInfo = field(default_factory=AccessInfo)
    gdpr: GDPRInfo = field(default_factory=GDPRInfo)
    pii: PIIInfo = field(default_factory=PIIInfo)
    data_classification: DataClassificationInfo = field(default_factory=DataClassificationInfo)
    model_governance: ModelGovernanceInfo = field(default_factory=ModelGovernanceInfo)
    ai_act: AIActInfo = field(default_factory=AIActInfo)
    content_policy: ContentPolicyInfo = field(default_factory=ContentPolicyInfo)
    data_lineage: DataLineageInfo = field(default_factory=DataLineageInfo)
    retention: RetentionInfo = field(default_factory=RetentionInfo)
    request_response: RequestResponseInfo = field(default_factory=RequestResponseInfo)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for Elasticsearch indexing."""
        doc = {
            "@timestamp": self.timestamp.isoformat(),
            "event_type": self.event_type.value,
            "request_id": self.request_id,
            "trace_id": self.trace_id,
            "environment": self.environment,
            "audit": {
                "action": self.audit.action.value,
                "resource_type": self.audit.resource_type,
                "resource_id": self.audit.resource_id,
                "outcome": self.audit.outcome.value,
                "reason": self.audit.reason,
            },
            "actor": {
                "type": self.actor.type.value,
                "id": self.actor.id,
                "name": self.actor.name,
                "email_hash": self.actor.email_hash,
                "role": self.actor.role,
                "department": self.actor.department,
                "api_key_id": self.actor.api_key_id,
                "service_account": self.actor.service_account,
            },
            "access": {
                "ip_address_hash": self.access.ip_address_hash,
                "user_agent": self.access.user_agent,
                "device_type": self.access.device_type,
                "authentication_method": self.access.authentication_method,
                "mfa_used": self.access.mfa_used,
                "session_id": self.access.session_id,
                "session_duration_seconds": self.access.session_duration_seconds,
            },
            "gdpr": {
                "data_subject_id_hash": self.gdpr.data_subject_id_hash,
                "processing_basis": self.gdpr.processing_basis.value,
                "data_categories": self.gdpr.data_categories,
                "special_categories": self.gdpr.special_categories,
                "retention_period_days": self.gdpr.retention_period_days,
                "cross_border_transfer": self.gdpr.cross_border_transfer,
                "transfer_mechanism": self.gdpr.transfer_mechanism,
                "dpia_required": self.gdpr.dpia_required,
                "dpia_reference": self.gdpr.dpia_reference,
                "consent": {
                    "given": self.gdpr.consent.given,
                    "version": self.gdpr.consent.version,
                    "purposes": self.gdpr.consent.purposes,
                    "withdrawable": self.gdpr.consent.withdrawable,
                },
            },
            "pii": {
                "detected": self.pii.detected,
                "types": [t.value for t in self.pii.types],
                "count": self.pii.count,
                "redacted": self.pii.redacted,
                "redaction_method": self.pii.redaction_method.value,
                "detection_confidence": self.pii.detection_confidence,
            },
            "data_classification": {
                "level": self.data_classification.level.value,
                "categories": self.data_classification.categories,
                "handling_instructions": self.data_classification.handling_instructions,
                "encryption_required": self.data_classification.encryption_required,
                "encrypted": self.data_classification.encrypted,
                "encryption_algorithm": self.data_classification.encryption_algorithm,
            },
            "model_governance": {
                "model_id": self.model_governance.model_id,
                "model_version": self.model_governance.model_version,
                "model_name": self.model_governance.model_name,
                "provider": self.model_governance.provider,
                "approval_status": self.model_governance.approval_status.value,
                "approved_by": self.model_governance.approved_by,
                "risk_level": self.model_governance.risk_level.value,
                "risk_assessment_id": self.model_governance.risk_assessment_id,
                "use_case_approved": self.model_governance.use_case_approved,
                "restrictions": self.model_governance.restrictions,
                "documentation_url": self.model_governance.documentation_url,
            },
            "ai_act": {
                "risk_category": self.ai_act.risk_category.value,
                "transparency_obligations_met": self.ai_act.transparency_obligations_met,
                "human_oversight_required": self.ai_act.human_oversight_required,
                "human_oversight_present": self.ai_act.human_oversight_present,
                "technical_documentation": self.ai_act.technical_documentation,
                "conformity_assessment": self.ai_act.conformity_assessment,
            },
            "content_policy": {
                "policy_version": self.content_policy.policy_version,
                "violation_detected": self.content_policy.violation_detected,
                "violation_type": self.content_policy.violation_type,
                "action_taken": self.content_policy.action_taken.value,
                "review_required": self.content_policy.review_required,
                "reviewed_by": self.content_policy.reviewed_by,
            },
            "data_lineage": {
                "source_systems": self.data_lineage.source_systems,
                "processing_steps": self.data_lineage.processing_steps,
                "transformations": self.data_lineage.transformations,
                "output_destinations": self.data_lineage.output_destinations,
            },
            "retention": {
                "policy_name": self.retention.policy_name,
                "retention_days": self.retention.retention_days,
                "legal_hold": self.retention.legal_hold,
                "legal_hold_reason": self.retention.legal_hold_reason,
            },
            "request_response": {
                "prompt_hash": self.request_response.prompt_hash,
                "prompt_length": self.request_response.prompt_length,
                "response_hash": self.request_response.response_hash,
                "response_length": self.request_response.response_length,
                "stored": self.request_response.stored,
                "storage_location": self.request_response.storage_location,
            },
        }

        # Add optional timestamps
        if self.gdpr.consent.timestamp:
            doc["gdpr"]["consent"]["timestamp"] = self.gdpr.consent.timestamp.isoformat()
        if self.gdpr.deletion_scheduled:
            doc["gdpr"]["deletion_scheduled"] = self.gdpr.deletion_scheduled.isoformat()
        if self.model_governance.approved_at:
            doc["model_governance"]["approved_at"] = self.model_governance.approved_at.isoformat()
        if self.content_policy.reviewed_at:
            doc["content_policy"]["reviewed_at"] = self.content_policy.reviewed_at.isoformat()
        if self.retention.deletion_date:
            doc["retention"]["deletion_date"] = self.retention.deletion_date.isoformat()

        # Add geo info
        if self.access.country:
            doc["access"]["geo"] = {
                "country": self.access.country,
                "region": self.access.region,
                "city": self.access.city,
            }

        # Add audit changes
        if self.audit.changes:
            doc["audit"]["changes"] = self.audit.changes

        # Add metadata
        if self.metadata:
            doc["metadata"] = self.metadata

        return doc


class ComplianceMonitor:
    """
    Compliance monitoring for AI systems.

    Tracks GDPR compliance, audit logs, data classification,
    model governance, and content policy enforcement.
    """

    def __init__(self, config: Config):
        """
        Initialize the compliance monitor.

        Args:
            config: Configuration object
        """
        self.config = config
        self.compliance_config = config.compliance
        self._metrics_buffer: List[ComplianceMetric] = []
        self._buffer_lock = Lock()

        # Model registry
        self._approved_models: Dict[str, ModelGovernanceInfo] = {}

        # Consent records
        self._consent_records: Dict[str, ConsentInfo] = {}

        # PII patterns
        self._pii_patterns = {
            PIIType.EMAIL: r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}',
            PIIType.PHONE: r'(\+\d{1,3}[-.]?)?\(?\d{3}\)?[-.]?\d{3}[-.]?\d{4}',
            PIIType.SSN: r'\b\d{3}[-]?\d{2}[-]?\d{4}\b',
            PIIType.CREDIT_CARD: r'\b\d{4}[-]?\d{4}[-]?\d{4}[-]?\d{4}\b',
            PIIType.IP_ADDRESS: r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b',
            PIIType.DATE_OF_BIRTH: r'\b\d{1,2}[/-]\d{1,2}[/-]\d{2,4}\b',
        }

        # Retention schedules
        self._retention_schedules: Dict[str, int] = {
            "default": 90,
            "audit": 365,
            "compliance": 2555,  # 7 years
            "legal_hold": 3650,  # 10 years
        }

    def _hash_value(self, value: str) -> str:
        """Hash a value for privacy."""
        return hashlib.sha256(value.encode()).hexdigest()[:16]

    def detect_pii(self, text: str) -> PIIInfo:
        """
        Detect PII in text.

        Args:
            text: Text to analyze

        Returns:
            PII detection information
        """
        pii_info = PIIInfo()
        detected_types: Set[PIIType] = set()
        total_count = 0

        for pii_type, pattern in self._pii_patterns.items():
            matches = re.findall(pattern, text, re.IGNORECASE)
            if matches:
                detected_types.add(pii_type)
                total_count += len(matches)

        pii_info.detected = len(detected_types) > 0
        pii_info.types = list(detected_types)
        pii_info.count = total_count
        pii_info.detection_confidence = min(1.0, total_count * 0.2) if detected_types else 0.0

        return pii_info

    def redact_pii(self, text: str, method: RedactionMethod = RedactionMethod.MASK) -> str:
        """
        Redact PII from text.

        Args:
            text: Text to redact
            method: Redaction method

        Returns:
            Redacted text
        """
        redacted = text

        for pii_type, pattern in self._pii_patterns.items():
            if method == RedactionMethod.MASK:
                redacted = re.sub(pattern, '[REDACTED]', redacted)
            elif method == RedactionMethod.HASH:
                def hash_match(match):
                    return f'[{self._hash_value(match.group())}]'
                redacted = re.sub(pattern, hash_match, redacted)
            elif method == RedactionMethod.REMOVE:
                redacted = re.sub(pattern, '', redacted)

        return redacted

    def record_audit_event(
        self,
        action: AuditAction,
        resource_type: str,
        resource_id: str,
        actor_id: str,
        outcome: AuditOutcome = AuditOutcome.SUCCESS,
        **kwargs
    ) -> ComplianceMetric:
        """
        Record an audit event.

        Args:
            action: Type of action
            resource_type: Type of resource
            resource_id: Resource identifier
            actor_id: Actor identifier
            outcome: Action outcome
            **kwargs: Additional fields

        Returns:
            The recorded metric
        """
        metric = ComplianceMetric(
            event_type=ComplianceEventType.AUDIT,
            request_id=kwargs.get('request_id', ''),
            trace_id=kwargs.get('trace_id', ''),
            environment=kwargs.get('environment', 'production'),
        )

        # Build audit info
        metric.audit = AuditInfo(
            action=action,
            resource_type=resource_type,
            resource_id=resource_id,
            outcome=outcome,
            reason=kwargs.get('reason', ''),
            changes=kwargs.get('changes', []),
        )

        # Build actor info
        metric.actor = ActorInfo(
            type=kwargs.get('actor_type', ActorType.USER),
            id=actor_id,
            name=kwargs.get('actor_name', ''),
            email_hash=self._hash_value(kwargs.get('actor_email', '')),
            role=kwargs.get('actor_role', ''),
            department=kwargs.get('actor_department', ''),
            api_key_id=kwargs.get('api_key_id', ''),
            service_account=kwargs.get('service_account', False),
        )

        # Build access info
        ip_address = kwargs.get('ip_address', '')
        metric.access = AccessInfo(
            ip_address_hash=self._hash_value(ip_address) if ip_address else '',
            country=kwargs.get('country', ''),
            region=kwargs.get('region', ''),
            city=kwargs.get('city', ''),
            user_agent=kwargs.get('user_agent', ''),
            device_type=kwargs.get('device_type', ''),
            authentication_method=kwargs.get('auth_method', ''),
            mfa_used=kwargs.get('mfa_used', False),
            session_id=kwargs.get('session_id', ''),
        )

        with self._buffer_lock:
            self._metrics_buffer.append(metric)

        return metric

    def record_ai_request(
        self,
        request_id: str,
        prompt: str,
        response: str,
        provider: str,
        model: str,
        actor_id: str,
        **kwargs
    ) -> ComplianceMetric:
        """
        Record an AI request for compliance.

        Args:
            request_id: Request identifier
            prompt: Input prompt
            response: Generated response
            provider: AI provider
            model: Model name
            actor_id: Actor identifier
            **kwargs: Additional fields

        Returns:
            The recorded metric
        """
        metric = ComplianceMetric(
            event_type=ComplianceEventType.AUDIT,
            request_id=request_id,
            trace_id=kwargs.get('trace_id', ''),
            environment=kwargs.get('environment', 'production'),
        )

        # Audit info
        metric.audit = AuditInfo(
            action=AuditAction.EXECUTE,
            resource_type="ai_model",
            resource_id=f"{provider}/{model}",
            outcome=AuditOutcome.SUCCESS,
        )

        # Actor info
        metric.actor = ActorInfo(
            type=kwargs.get('actor_type', ActorType.USER),
            id=actor_id,
            name=kwargs.get('actor_name', ''),
            email_hash=self._hash_value(kwargs.get('actor_email', '')),
            role=kwargs.get('actor_role', ''),
        )

        # Detect PII
        prompt_pii = self.detect_pii(prompt)
        response_pii = self.detect_pii(response)

        metric.pii = PIIInfo(
            detected=prompt_pii.detected or response_pii.detected,
            types=list(set(prompt_pii.types + response_pii.types)),
            count=prompt_pii.count + response_pii.count,
            redacted=kwargs.get('pii_redacted', False),
            redaction_method=kwargs.get('redaction_method', RedactionMethod.MASK),
            detection_confidence=max(prompt_pii.detection_confidence, response_pii.detection_confidence),
        )

        # Request/response info (hashed for privacy)
        metric.request_response = RequestResponseInfo(
            prompt_hash=self._hash_value(prompt),
            prompt_length=len(prompt),
            response_hash=self._hash_value(response),
            response_length=len(response),
            stored=kwargs.get('stored', True),
            storage_location=kwargs.get('storage_location', ''),
        )

        # Model governance
        metric.model_governance = ModelGovernanceInfo(
            model_id=f"{provider}/{model}",
            model_name=model,
            provider=provider,
            approval_status=self._get_model_approval_status(provider, model),
            risk_level=kwargs.get('risk_level', RiskLevel.LIMITED),
        )

        # Data classification
        metric.data_classification = DataClassificationInfo(
            level=kwargs.get('classification_level', DataClassificationLevel.INTERNAL),
            categories=kwargs.get('data_categories', []),
            encryption_required=kwargs.get('encryption_required', False),
            encrypted=kwargs.get('encrypted', True),
        )

        # GDPR info
        data_subject_id = kwargs.get('data_subject_id', actor_id)
        metric.gdpr = GDPRInfo(
            data_subject_id_hash=self._hash_value(data_subject_id),
            processing_basis=kwargs.get('processing_basis', ProcessingBasis.LEGITIMATE_INTEREST),
            consent=self._consent_records.get(data_subject_id, ConsentInfo()),
            data_categories=kwargs.get('data_categories', []),
            retention_period_days=self.compliance_config.gdpr.data_retention_days,
            deletion_scheduled=datetime.now(timezone.utc) + timedelta(
                days=self.compliance_config.gdpr.data_retention_days
            ),
        )

        # AI Act compliance
        metric.ai_act = AIActInfo(
            risk_category=kwargs.get('ai_act_risk', AIActRiskCategory.LIMITED),
            transparency_obligations_met=True,
            human_oversight_required=kwargs.get('human_oversight_required', False),
            human_oversight_present=kwargs.get('human_oversight_present', False),
        )

        # Content policy
        metric.content_policy = ContentPolicyInfo(
            policy_version=kwargs.get('policy_version', '1.0'),
            violation_detected=kwargs.get('policy_violation', False),
            violation_type=kwargs.get('violation_type', ''),
            action_taken=kwargs.get('policy_action', ContentPolicyAction.ALLOWED),
            review_required=kwargs.get('review_required', False),
        )

        # Retention
        metric.retention = RetentionInfo(
            policy_name=kwargs.get('retention_policy', 'default'),
            retention_days=self._retention_schedules.get(
                kwargs.get('retention_policy', 'default'), 90
            ),
            deletion_date=datetime.now(timezone.utc) + timedelta(
                days=self._retention_schedules.get(
                    kwargs.get('retention_policy', 'default'), 90
                )
            ),
            legal_hold=kwargs.get('legal_hold', False),
        )

        with self._buffer_lock:
            self._metrics_buffer.append(metric)

        return metric

    def _get_model_approval_status(self, provider: str, model: str) -> ModelApprovalStatus:
        """Get approval status for a model."""
        model_key = f"{provider}/{model}"
        if model_key in self._approved_models:
            return self._approved_models[model_key].approval_status
        return ModelApprovalStatus.PENDING

    def register_model_approval(
        self,
        provider: str,
        model: str,
        model_version: str,
        approved_by: str,
        risk_level: RiskLevel = RiskLevel.LIMITED,
        use_cases: List[str] = None,
        restrictions: List[str] = None,
        **kwargs
    ) -> ModelGovernanceInfo:
        """
        Register model approval.

        Args:
            provider: AI provider
            model: Model name
            model_version: Model version
            approved_by: Approver identifier
            risk_level: Risk level
            use_cases: Approved use cases
            restrictions: Usage restrictions
            **kwargs: Additional fields

        Returns:
            Model governance info
        """
        model_key = f"{provider}/{model}"

        governance = ModelGovernanceInfo(
            model_id=model_key,
            model_version=model_version,
            model_name=model,
            provider=provider,
            approval_status=ModelApprovalStatus.APPROVED,
            approved_by=approved_by,
            approved_at=datetime.now(timezone.utc),
            risk_level=risk_level,
            risk_assessment_id=kwargs.get('risk_assessment_id', ''),
            use_case_approved=use_cases or [],
            restrictions=restrictions or [],
            documentation_url=kwargs.get('documentation_url', ''),
        )

        self._approved_models[model_key] = governance

        # Record the approval event
        metric = ComplianceMetric(
            event_type=ComplianceEventType.MODEL_APPROVAL,
            model_governance=governance,
        )

        metric.audit = AuditInfo(
            action=AuditAction.UPDATE,
            resource_type="model_approval",
            resource_id=model_key,
            outcome=AuditOutcome.SUCCESS,
        )

        with self._buffer_lock:
            self._metrics_buffer.append(metric)

        logger.info(f"Model {model_key} approved by {approved_by}")
        return governance

    def record_consent(
        self,
        data_subject_id: str,
        given: bool,
        purposes: List[str],
        version: str = "1.0",
        **kwargs
    ) -> ComplianceMetric:
        """
        Record consent for data processing.

        Args:
            data_subject_id: Data subject identifier
            given: Whether consent was given
            purposes: Purposes for consent
            version: Consent version
            **kwargs: Additional fields

        Returns:
            The recorded metric
        """
        consent = ConsentInfo(
            given=given,
            timestamp=datetime.now(timezone.utc),
            version=version,
            purposes=purposes,
            withdrawable=kwargs.get('withdrawable', True),
        )

        self._consent_records[data_subject_id] = consent

        metric = ComplianceMetric(
            event_type=ComplianceEventType.CONSENT,
        )

        metric.gdpr = GDPRInfo(
            data_subject_id_hash=self._hash_value(data_subject_id),
            consent=consent,
            processing_basis=ProcessingBasis.CONSENT if given else ProcessingBasis.LEGITIMATE_INTEREST,
        )

        metric.audit = AuditInfo(
            action=AuditAction.UPDATE if given else AuditAction.DELETE,
            resource_type="consent",
            resource_id=self._hash_value(data_subject_id),
            outcome=AuditOutcome.SUCCESS,
        )

        with self._buffer_lock:
            self._metrics_buffer.append(metric)

        return metric

    def process_deletion_request(
        self,
        data_subject_id: str,
        requester_id: str,
        **kwargs
    ) -> ComplianceMetric:
        """
        Process a data deletion request (GDPR right to be forgotten).

        Args:
            data_subject_id: Data subject identifier
            requester_id: Requester identifier
            **kwargs: Additional fields

        Returns:
            The recorded metric
        """
        metric = ComplianceMetric(
            event_type=ComplianceEventType.DATA_DELETION,
        )

        metric.gdpr = GDPRInfo(
            data_subject_id_hash=self._hash_value(data_subject_id),
            processing_basis=ProcessingBasis.CONSENT,
        )

        metric.audit = AuditInfo(
            action=AuditAction.DELETE,
            resource_type="user_data",
            resource_id=self._hash_value(data_subject_id),
            outcome=AuditOutcome.SUCCESS,
            reason="GDPR deletion request",
        )

        metric.actor = ActorInfo(
            type=ActorType.USER,
            id=requester_id,
        )

        # Remove consent record
        if data_subject_id in self._consent_records:
            del self._consent_records[data_subject_id]

        with self._buffer_lock:
            self._metrics_buffer.append(metric)

        logger.info(f"Data deletion request processed for {self._hash_value(data_subject_id)}")
        return metric

    def check_compliance_violations(self) -> List[Dict[str, Any]]:
        """
        Check for compliance violations.

        Returns:
            List of violations
        """
        violations = []

        with self._buffer_lock:
            for metric in self._metrics_buffer:
                # Check for PII without consent
                if metric.pii.detected and not metric.gdpr.consent.given:
                    violations.append({
                        "type": "pii_without_consent",
                        "severity": "high",
                        "request_id": metric.request_id,
                        "pii_types": [t.value for t in metric.pii.types],
                    })

                # Check for unapproved model usage
                if metric.model_governance.approval_status == ModelApprovalStatus.PENDING:
                    violations.append({
                        "type": "unapproved_model",
                        "severity": "medium",
                        "request_id": metric.request_id,
                        "model": metric.model_governance.model_id,
                    })

                # Check for content policy violations
                if metric.content_policy.violation_detected:
                    violations.append({
                        "type": "content_policy_violation",
                        "severity": "high",
                        "request_id": metric.request_id,
                        "violation_type": metric.content_policy.violation_type,
                    })

                # Check for AI Act compliance
                if (metric.ai_act.human_oversight_required and
                    not metric.ai_act.human_oversight_present):
                    violations.append({
                        "type": "missing_human_oversight",
                        "severity": "high",
                        "request_id": metric.request_id,
                        "risk_category": metric.ai_act.risk_category.value,
                    })

        return violations

    def get_buffered_metrics(self, clear: bool = True) -> List[ComplianceMetric]:
        """Get buffered metrics."""
        with self._buffer_lock:
            metrics = self._metrics_buffer.copy()
            if clear:
                self._metrics_buffer.clear()
        return metrics

    def get_compliance_summary(self) -> Dict[str, Any]:
        """Get compliance summary."""
        with self._buffer_lock:
            total = len(self._metrics_buffer)
            if total == 0:
                return {
                    "total_events": 0,
                    "pii_detections": 0,
                    "policy_violations": 0,
                    "approved_models": len(self._approved_models),
                    "consent_records": len(self._consent_records),
                }

            pii_count = sum(1 for m in self._metrics_buffer if m.pii.detected)
            violations = sum(1 for m in self._metrics_buffer if m.content_policy.violation_detected)

            return {
                "total_events": total,
                "pii_detections": pii_count,
                "pii_detection_rate": pii_count / total,
                "policy_violations": violations,
                "violation_rate": violations / total,
                "approved_models": len(self._approved_models),
                "consent_records": len(self._consent_records),
                "active_violations": len(self.check_compliance_violations()),
            }
