import uuid
from datetime import datetime, timezone

from sqlalchemy import (
    JSON,
    Boolean,
    Column,
    DateTime,
    Enum,
    Float,
    ForeignKey,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import relationship

from .database import Base


def _uuid() -> str:
    return str(uuid.uuid4())


class Registry(Base):
    __tablename__ = "registries"

    id = Column(String, primary_key=True, default=_uuid)
    name = Column(String, nullable=False)
    url = Column(String, nullable=False)
    type = Column(
        Enum("acr", "docker_hub", "ghcr", "generic", name="registry_type_enum", create_type=False),
        nullable=False,
        default="acr",
    )
    auth_method = Column(
        Enum("managed_identity", "username_password", "none", name="registry_auth_enum", create_type=False),
        nullable=False,
        default="managed_identity",
    )
    username = Column(String, nullable=True)
    password = Column(String, nullable=True)
    auto_sync = Column(Boolean, default=True, nullable=False)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)
    last_synced_at = Column(DateTime, nullable=True)
    repository_cache = Column(JSON, nullable=True)  # {repo: [tag, ...], ...}

    scans = relationship("Scan", back_populates="registry")


class Scan(Base):
    __tablename__ = "scans"

    id = Column(String, primary_key=True, default=_uuid)
    name = Column(String, nullable=False)
    scan_type = Column(Enum("container", "dependency", "source", name="scan_type_enum", create_type=False), nullable=False)
    target = Column(String, nullable=False)
    status = Column(
        Enum("pending", "running", "completed", "failed", "unsupported", name="scan_status_enum", create_type=False),
        nullable=False,
        default="pending",
    )
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)
    completed_at = Column(DateTime, nullable=True)
    error_message = Column(String, nullable=True)     # human-readable reason for failed/unsupported
    scanner_engine = Column(String, nullable=True)    # e.g. "trivy", "grype", "osv"
    scanner_override = Column(String, nullable=True)  # force a specific backend for this scan (comparison scans)
    base_image = Column(String, nullable=True)        # e.g. "debian:bullseye-slim" (container scans only)
    base_image_chain = Column(JSON, nullable=True)    # e.g. ["scratch", "debian:bullseye-slim", "python:3.11-slim"]
    packages = Column(JSON, nullable=True)            # stored for dependency re-runs
    registry_id = Column(String, ForeignKey("registries.id"), nullable=True)  # set for registry-sourced scans
    team_id = Column(String, ForeignKey("teams.id"), nullable=True)  # owning team (auto-assigned via ownership rules)

    findings = relationship("Finding", back_populates="scan", cascade="all, delete-orphan")
    sbom = relationship("SBOM", back_populates="scan", uselist=False, cascade="all, delete-orphan")
    policy_results = relationship("PolicyResult", back_populates="scan", cascade="all, delete-orphan")
    registry = relationship("Registry", back_populates="scans")
    team = relationship("Team", back_populates="scans")


class Finding(Base):
    __tablename__ = "findings"

    id = Column(String, primary_key=True, default=_uuid)
    scan_id = Column(String, ForeignKey("scans.id"), nullable=False)

    package_name = Column(String, nullable=False)
    package_version = Column(String, nullable=False)
    package_ecosystem = Column(String, nullable=False)

    vulnerability_id = Column(String, nullable=False)
    severity = Column(
        Enum("CRITICAL", "HIGH", "MEDIUM", "LOW", "NEGLIGIBLE", "UNKNOWN", name="severity_enum", create_type=False),
        nullable=False,
        default="UNKNOWN",
    )
    cvss_score = Column(Float, nullable=True)
    description = Column(Text, nullable=True)
    fix_version = Column(String, nullable=True)
    is_fixed = Column(Boolean, default=False, nullable=False)
    reachable = Column(Boolean, default=False, nullable=False)
    exploitable = Column(Boolean, default=False, nullable=False)
    risk_accepted = Column(Boolean, default=False, nullable=False)
    risk_accepted_at = Column(DateTime, nullable=True)
    risk_score = Column(Float, default=0.0, nullable=False)
    aliases = Column(JSON, default=list)
    references = Column(JSON, default=list)

    scan = relationship("Scan", back_populates="findings")
    tickets = relationship("Ticket", back_populates="finding")


class Policy(Base):
    __tablename__ = "policies"

    id = Column(String, primary_key=True, default=_uuid)
    name = Column(String, nullable=False)
    description = Column(String, nullable=True)
    enabled = Column(Boolean, default=True, nullable=False)
    rules = Column(JSON, default=list)
    action = Column(
        Enum("block", "warn", "audit", name="policy_action_enum", create_type=False),
        nullable=False,
        default="warn",
    )
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)
    updated_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc), nullable=False)

    policy_results = relationship("PolicyResult", back_populates="policy", cascade="all, delete-orphan")


class PolicyResult(Base):
    __tablename__ = "policy_results"

    id = Column(String, primary_key=True, default=_uuid)
    scan_id = Column(String, ForeignKey("scans.id"), nullable=False)
    policy_id = Column(String, ForeignKey("policies.id"), nullable=False)
    passed = Column(Boolean, nullable=False)
    violations = Column(JSON, default=list)
    evaluated_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)

    scan = relationship("Scan", back_populates="policy_results")
    policy = relationship("Policy", back_populates="policy_results")


class SBOM(Base):
    __tablename__ = "sboms"

    id = Column(String, primary_key=True, default=_uuid)
    scan_id = Column(String, ForeignKey("scans.id"), nullable=False)
    format = Column(Enum("cyclonedx", "spdx", name="sbom_format_enum", create_type=False), nullable=False, default="cyclonedx")
    spec_version = Column(String, nullable=False)
    content = Column(JSON, nullable=False)
    components_count = Column(Integer, default=0, nullable=False)
    generated_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)

    scan = relationship("Scan", back_populates="sbom")


class AuditLog(Base):
    __tablename__ = "audit_logs"

    id = Column(String, primary_key=True, default=_uuid)
    action = Column(String, nullable=False)
    resource_type = Column(String, nullable=False)
    resource_id = Column(String, nullable=True)
    details = Column(JSON, default=dict)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)


class Team(Base):
    __tablename__ = "teams"

    id = Column(String, primary_key=True, default=_uuid)
    name = Column(String, nullable=False, unique=True)
    description = Column(String, nullable=True)
    contact_email = Column(String, nullable=True)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)
    updated_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc), nullable=False)
    # --- Auto-ticketing configuration ---
    integration_id = Column(String, ForeignKey("integrations.id", ondelete="SET NULL"), nullable=True)
    auto_create_tickets = Column(Boolean, default=False, nullable=False)
    ticket_severity_threshold = Column(
        Enum("CRITICAL", "HIGH", "MEDIUM", "LOW", name="severity_enum", create_type=False),
        nullable=False,
        default="HIGH",
    )

    ownership_rules = relationship("OwnershipRule", back_populates="team", cascade="all, delete-orphan")
    scans = relationship("Scan", back_populates="team")
    integration = relationship("Integration", foreign_keys=[integration_id])


class OwnershipRule(Base):
    __tablename__ = "ownership_rules"

    id = Column(String, primary_key=True, default=_uuid)
    team_id = Column(String, ForeignKey("teams.id"), nullable=False)
    # Glob pattern matched against scan target (e.g. "myregistry.io/frontend-*")
    pattern = Column(String, nullable=False)
    # Optional: restrict to a scan type (container/source/dependency); null = match all
    scan_type = Column(String, nullable=True)
    # Higher priority wins when multiple rules match (default 0)
    priority = Column(Integer, default=0, nullable=False)
    description = Column(String, nullable=True)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)

    team = relationship("Team", back_populates="ownership_rules")


class VulnerabilityInstance(Base):
    """Tracks unique vulnerability instances across scans.

    Keyed on (vulnerability_id, package_name, target).  Upserted after each
    scan completes — inserted on first occurrence, updated on subsequent scans.
    Used for deduplication in dashboard/report queries and first-seen tracking.
    """
    __tablename__ = "vulnerability_instances"
    __table_args__ = (
        UniqueConstraint("vulnerability_id", "package_name", "target", name="uq_vuln_pkg_target"),
    )

    id = Column(String, primary_key=True, default=_uuid)
    vulnerability_id = Column(String, nullable=False, index=True)
    package_name = Column(String, nullable=False)
    target = Column(String, nullable=False)

    # Latest state (updated each time the same vuln is seen again)
    severity = Column(
        Enum("CRITICAL", "HIGH", "MEDIUM", "LOW", "NEGLIGIBLE", "UNKNOWN", name="severity_enum", create_type=False),
        nullable=False,
        default="UNKNOWN",
    )
    cvss_score = Column(Float, nullable=True)
    package_version = Column(String, nullable=False)  # latest observed version
    package_ecosystem = Column(String, nullable=False)
    is_fixed = Column(Boolean, default=False, nullable=False)
    fix_version = Column(String, nullable=True)
    risk_score = Column(Float, default=0.0, nullable=False)

    # Tracking timestamps
    first_seen_at = Column(DateTime, nullable=False)
    last_seen_at = Column(DateTime, nullable=False)

    # Link to the scan where this vuln was first and last observed
    first_scan_id = Column(String, ForeignKey("scans.id", ondelete="SET NULL"), nullable=True)
    last_scan_id = Column(String, ForeignKey("scans.id", ondelete="SET NULL"), nullable=True)

    # Optional team linkage (derived from the scan's team)
    team_id = Column(String, ForeignKey("teams.id", ondelete="SET NULL"), nullable=True)


class AppSetting(Base):
    __tablename__ = "app_settings"

    key = Column(String, primary_key=True)
    value = Column(String, nullable=False)
    description = Column(String, nullable=True)
    updated_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc), nullable=False)


class Integration(Base):
    __tablename__ = "integrations"

    id = Column(String, primary_key=True, default=_uuid)
    name = Column(String, nullable=False)
    provider = Column(
        Enum("jira", "servicenow", "linear", "github_issues", name="integration_provider_enum", create_type=False),
        nullable=False,
    )
    enabled = Column(Boolean, default=True, nullable=False)
    base_url = Column(String, nullable=False)
    auth_method = Column(
        Enum("basic", "api_token", "oauth2", "pat", name="integration_auth_enum", create_type=False),
        nullable=False,
        default="api_token",
    )
    auth_username = Column(String, nullable=True)
    auth_secret = Column(String, nullable=True)
    provider_config = Column(JSON, default=dict)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)
    updated_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc), nullable=False)

    field_mappings = relationship("IntegrationFieldMapping", back_populates="integration", cascade="all, delete-orphan")
    tickets = relationship("Ticket", back_populates="integration", cascade="all, delete-orphan")
    webhook_secret = Column(String, nullable=True)  # HMAC secret for webhook verification
    webhook_registrations = relationship("WebhookRegistration", back_populates="integration", cascade="all, delete-orphan")
    automation_rules = relationship("AutomationRule", back_populates="integration")


class IntegrationFieldMapping(Base):
    __tablename__ = "integration_field_mappings"

    id = Column(String, primary_key=True, default=_uuid)
    integration_id = Column(String, ForeignKey("integrations.id"), nullable=False)
    source = Column(String, nullable=False)
    target_field = Column(String, nullable=False)
    transform = Column(String, nullable=True)
    template_value = Column(String, nullable=True)
    priority = Column(Integer, default=0, nullable=False)

    integration = relationship("Integration", back_populates="field_mappings")


class Ticket(Base):
    __tablename__ = "tickets"
    __table_args__ = (
        UniqueConstraint("integration_id", "finding_id", name="uq_integration_finding"),
    )

    id = Column(String, primary_key=True, default=_uuid)
    integration_id = Column(String, ForeignKey("integrations.id"), nullable=False)
    finding_id = Column(String, ForeignKey("findings.id", ondelete="SET NULL"), nullable=True)
    external_id = Column(String, nullable=False, index=True)
    external_key = Column(String, nullable=False, index=True)
    external_url = Column(String, nullable=False)
    external_status = Column(String, nullable=True)
    summary = Column(String, nullable=False)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)
    synced_at = Column(DateTime, nullable=True)
    external_assignee = Column(String, nullable=True)
    external_priority = Column(String, nullable=True)

    integration = relationship("Integration", back_populates="tickets")
    finding = relationship("Finding", back_populates="tickets")
    comments = relationship("TicketComment", back_populates="ticket", cascade="all, delete-orphan")


class WebhookEvent(Base):
    __tablename__ = "webhook_events"

    id = Column(String, primary_key=True, default=_uuid)
    integration_id = Column(String, ForeignKey("integrations.id"), nullable=False)
    event_type = Column(String, nullable=False)  # e.g. "jira:issue_updated"
    external_issue_id = Column(String, nullable=True)
    external_issue_key = Column(String, nullable=True)
    payload = Column(JSON, nullable=False)
    status = Column(
        Enum("received", "processing", "processed", "failed", "ignored", name="webhook_event_status_enum", create_type=False),
        nullable=False,
        default="received",
    )
    error_message = Column(String, nullable=True)
    received_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)
    processed_at = Column(DateTime, nullable=True)

    integration = relationship("Integration")


class WebhookRegistration(Base):
    __tablename__ = "webhook_registrations"

    id = Column(String, primary_key=True, default=_uuid)
    integration_id = Column(String, ForeignKey("integrations.id"), nullable=False, unique=True)
    external_webhook_id = Column(String, nullable=True)  # ID returned by Jira when registering
    callback_url = Column(String, nullable=False)
    jira_events = Column(JSON, default=list)  # e.g. ["jira:issue_updated", "jira:issue_deleted"]
    secret = Column(String, nullable=True)  # HMAC verification secret
    is_cloud = Column(Boolean, default=True, nullable=False)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)
    updated_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc), nullable=False)

    integration = relationship("Integration", back_populates="webhook_registrations")


class TicketComment(Base):
    __tablename__ = "ticket_comments"
    __table_args__ = (
        UniqueConstraint(
            "ticket_id", "external_comment_id",
            name="uq_ticket_comment_external",
        ),
    )

    id = Column(String, primary_key=True, default=_uuid)
    ticket_id = Column(String, ForeignKey("tickets.id"), nullable=False)
    external_comment_id = Column(String, nullable=True)
    author = Column(String, nullable=True)
    body = Column(Text, nullable=False)
    direction = Column(
        Enum("inbound", "outbound", name="comment_direction_enum", create_type=False),
        nullable=False,
    )
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)

    ticket = relationship("Ticket", back_populates="comments")


class AutomationRule(Base):
    __tablename__ = "automation_rules"

    id = Column(String, primary_key=True, default=_uuid)
    name = Column(String, nullable=False)
    description = Column(String, nullable=True)
    enabled = Column(Boolean, default=True, nullable=False)
    trigger = Column(String, nullable=False)  # e.g. "jira_status_changed", "scan_completed"
    conditions = Column(JSON, default=list)  # list of condition dicts
    actions = Column(JSON, default=list)  # list of action dicts
    integration_id = Column(String, ForeignKey("integrations.id", ondelete="SET NULL"), nullable=True)
    team_id = Column(String, ForeignKey("teams.id", ondelete="SET NULL"), nullable=True)
    execution_count = Column(Integer, default=0, nullable=False)
    last_executed_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)
    updated_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc), nullable=False)

    integration = relationship("Integration", back_populates="automation_rules")
    team = relationship("Team")
    executions = relationship("AutomationRuleExecution", back_populates="rule", cascade="all, delete-orphan")


class AutomationRuleExecution(Base):
    __tablename__ = "automation_rule_executions"

    id = Column(String, primary_key=True, default=_uuid)
    rule_id = Column(String, ForeignKey("automation_rules.id"), nullable=False)
    trigger_event = Column(String, nullable=False)
    trigger_context = Column(JSON, default=dict)
    conditions_matched = Column(Boolean, nullable=False)
    actions_executed = Column(JSON, default=list)  # list of {action_type, success, detail}
    status = Column(
        Enum("success", "partial_failure", "failed", "skipped", name="automation_exec_status_enum", create_type=False),
        nullable=False,
    )
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)

    rule = relationship("AutomationRule", back_populates="executions")
