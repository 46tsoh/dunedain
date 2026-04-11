from __future__ import annotations

from datetime import datetime
from typing import Any, Optional

from pydantic import BaseModel, Field, model_validator


# ---------------------------------------------------------------------------
# Finding
# ---------------------------------------------------------------------------

class FindingBase(BaseModel):
    package_name: str
    package_version: str
    package_ecosystem: str
    vulnerability_id: str
    severity: str = "UNKNOWN"
    cvss_score: Optional[float] = None
    description: Optional[str] = None
    fix_version: Optional[str] = None
    is_fixed: bool = False
    reachable: bool = False
    exploitable: bool = False
    risk_score: float = 0.0
    aliases: list[str] = Field(default_factory=list)
    references: list[str] = Field(default_factory=list)


class FindingCreate(FindingBase):
    scan_id: str


class FindingRead(FindingBase):
    id: str
    scan_id: str

    model_config = {"from_attributes": True}


# ---------------------------------------------------------------------------
# SBOM
# ---------------------------------------------------------------------------

class SBOMBase(BaseModel):
    format: str = "cyclonedx"
    spec_version: str
    content: dict[str, Any]
    components_count: int = 0


class SBOMCreate(SBOMBase):
    scan_id: str


class SBOMRead(SBOMBase):
    id: str
    scan_id: str
    generated_at: datetime
    components: list[dict[str, Any]] = Field(default_factory=list)

    model_config = {"from_attributes": True}

    @model_validator(mode="after")
    def extract_components(self) -> "SBOMRead":
        """Extract and normalize component data from the raw CycloneDX content dict.

        Maps each entry in ``content["components"]`` to a dict with ``name``,
        ``version``, ``purl``, ``ecosystem``, and ``licenses`` keys so that the
        frontend can render the component table without parsing raw SBOM JSON.
        """
        if self.content:
            raw_components = self.content.get("components", [])
            self.components = [
                {
                    "name": c.get("name", ""),
                    "version": c.get("version", ""),
                    "purl": c.get("purl"),
                    "ecosystem": c.get("ecosystem", "unknown"),
                    "licenses": c.get("licenses", []),
                }
                for c in raw_components
            ]
        return self


# ---------------------------------------------------------------------------
# Policy
# ---------------------------------------------------------------------------

class PolicyBase(BaseModel):
    name: str
    description: Optional[str] = None
    enabled: bool = True
    rules: list[dict[str, Any]] = Field(default_factory=list)
    action: str = "warn"


class PolicyCreate(PolicyBase):
    pass


class PolicyUpdate(PolicyBase):
    pass


class PolicyRead(PolicyBase):
    id: str
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}


# ---------------------------------------------------------------------------
# PolicyResult
# ---------------------------------------------------------------------------

def _compute_policy_status(passed: bool, policy_action: str) -> str:
    """Compute a display status string from a policy result.

    Returns 'pass' when the policy passed, 'warn' for non-blocking failures
    (action is 'warn' or 'audit'), and 'fail' for blocking failures.
    """
    if passed:
        return "pass"
    if policy_action in ("warn", "audit"):
        return "warn"
    return "fail"


class PolicyResultRead(BaseModel):
    id: str
    scan_id: str
    policy_id: str
    policy_name: str = ""
    passed: bool
    status: str = ""
    violations: list[dict[str, Any]]
    evaluated_at: datetime

    model_config = {"from_attributes": True}


# ---------------------------------------------------------------------------
# Scan
# ---------------------------------------------------------------------------

class ScanCreate(BaseModel):
    name: Optional[str] = None   # deprecated — auto-derived from target if omitted
    scan_type: str
    target: str
    packages: Optional[list[dict[str, Any]]] = None
    registry_id: Optional[str] = None
    scanner_override: Optional[str] = None  # e.g. "trivy", "grype", "osv_scanner"
    team_id: Optional[str] = None  # explicit team assignment (overrides ownership rules)


class ScanRead(BaseModel):
    id: str
    name: str
    scan_type: str
    target: str
    status: str
    error_message: Optional[str] = None
    created_at: datetime
    completed_at: Optional[datetime] = None
    scan_duration_seconds: Optional[float] = None
    scanner_engine: Optional[str] = None
    scanner_override: Optional[str] = None
    base_image: Optional[str] = None
    base_image_chain: Optional[list[str]] = None
    registry_id: Optional[str] = None
    registry_name: Optional[str] = None
    team_id: Optional[str] = None
    team_name: Optional[str] = None
    findings: list[FindingRead] = Field(default_factory=list)
    finding_count: int = 0
    findings_count: int = 0
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    negligible_count: int = 0
    unknown_count: int = 0

    model_config = {"from_attributes": True}

    @model_validator(mode="after")
    def compute_duration(self) -> "ScanRead":
        if self.completed_at and self.created_at and self.scan_duration_seconds is None:
            self.scan_duration_seconds = (self.completed_at - self.created_at).total_seconds()
        return self


class ScanSummary(BaseModel):
    id: str
    name: str
    scan_type: str
    target: str
    status: str
    error_message: Optional[str] = None
    created_at: datetime
    completed_at: Optional[datetime] = None
    scan_duration_seconds: Optional[float] = None
    scanner_engine: Optional[str] = None
    scanner_override: Optional[str] = None
    base_image: Optional[str] = None
    base_image_chain: Optional[list[str]] = None
    registry_id: Optional[str] = None
    registry_name: Optional[str] = None
    team_id: Optional[str] = None
    team_name: Optional[str] = None
    finding_count: int = 0
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    negligible_count: int = 0
    unknown_count: int = 0

    model_config = {"from_attributes": True}

    @model_validator(mode="after")
    def compute_duration(self) -> "ScanSummary":
        if self.completed_at and self.created_at and self.scan_duration_seconds is None:
            self.scan_duration_seconds = (self.completed_at - self.created_at).total_seconds()
        return self


# ---------------------------------------------------------------------------
# AuditLog
# ---------------------------------------------------------------------------

class AuditLogRead(BaseModel):
    id: str
    action: str
    resource_type: str
    resource_id: Optional[str] = None
    details: dict[str, Any]
    created_at: datetime

    model_config = {"from_attributes": True}


# ---------------------------------------------------------------------------
# SBOM ingest request
# ---------------------------------------------------------------------------

class SBOMIngestRequest(BaseModel):
    name: str
    content: dict[str, Any]
    format: str = "cyclonedx"


# ---------------------------------------------------------------------------
# Dashboard / Reports
# ---------------------------------------------------------------------------

class SeverityTrendPoint(BaseModel):
    date: str
    critical: int
    high: int
    medium: int
    low: int
    negligible: int = 0
    unknown: int = 0


class TopVulnerability(BaseModel):
    vulnerability_id: str
    count: int
    severity: str
    max_cvss: Optional[float]


class DashboardReport(BaseModel):
    total_scans: int
    total_findings: int
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int
    negligible_count: int = 0
    unknown_count: int = 0
    recent_scans: list[ScanSummary]
    top_vulnerabilities: list[TopVulnerability]
    severity_trend: list[SeverityTrendPoint]


# ---------------------------------------------------------------------------
# Settings
# ---------------------------------------------------------------------------

class SettingRead(BaseModel):
    key: str
    value: str
    description: Optional[str] = None
    updated_at: datetime

    model_config = {"from_attributes": True}


class SettingUpdate(BaseModel):
    value: str


# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------

class RegistryCreate(BaseModel):
    name: str
    url: str
    type: str = "acr"
    auth_method: str = "managed_identity"
    username: Optional[str] = None
    password: Optional[str] = None
    auto_sync: bool = True


class RegistryUpdate(BaseModel):
    name: Optional[str] = None
    url: Optional[str] = None
    auth_method: Optional[str] = None
    username: Optional[str] = None
    password: Optional[str] = None
    auto_sync: Optional[bool] = None


class RegistryRead(BaseModel):
    id: str
    name: str
    url: str
    type: str
    auth_method: str
    auto_sync: bool
    username: Optional[str] = None
    created_at: datetime
    last_synced_at: Optional[datetime] = None
    repository_cache: Optional[dict[str, list[str]]] = None

    model_config = {"from_attributes": True}


class RegistryTestResult(BaseModel):
    success: bool
    message: str
    repositories: Optional[list[str]] = None


# ---------------------------------------------------------------------------
# Team / Ownership
# ---------------------------------------------------------------------------

class OwnershipRuleBase(BaseModel):
    pattern: str
    scan_type: Optional[str] = None
    priority: int = 0
    description: Optional[str] = None


class OwnershipRuleCreate(OwnershipRuleBase):
    pass


class OwnershipRuleRead(OwnershipRuleBase):
    id: str
    team_id: str
    created_at: datetime

    model_config = {"from_attributes": True}


class TeamBase(BaseModel):
    name: str
    description: Optional[str] = None
    contact_email: Optional[str] = None
    integration_id: Optional[str] = None
    auto_create_tickets: bool = False
    ticket_severity_threshold: str = "HIGH"


class TeamCreate(TeamBase):
    pass


class TeamUpdate(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None
    contact_email: Optional[str] = None
    integration_id: Optional[str] = None
    auto_create_tickets: Optional[bool] = None
    ticket_severity_threshold: Optional[str] = None


class TeamRead(TeamBase):
    id: str
    created_at: datetime
    updated_at: datetime
    ownership_rules: list[OwnershipRuleRead] = Field(default_factory=list)
    scan_count: int = 0
    integration_name: Optional[str] = None

    model_config = {"from_attributes": True}


# ---------------------------------------------------------------------------
# Team Dashboard
# ---------------------------------------------------------------------------

class TeamFindingSummary(BaseModel):
    """A unique vulnerability instance with SLA context for the team dashboard."""
    finding_id: str
    vulnerability_id: str
    package_name: str
    package_version: str
    severity: str
    cvss_score: Optional[float] = None
    risk_score: float = 0.0
    is_fixed: bool = False
    fix_version: Optional[str] = None
    discovered_at: datetime       # first_seen_at of the vulnerability instance
    first_seen_at: Optional[datetime] = None  # explicit alias for frontend
    scan_id: str                  # first scan that found this vuln
    scan_name: str                # target name for display
    target: Optional[str] = None  # scan target (e.g. image name)
    sla_hours: Optional[int] = None
    hours_elapsed: float = 0.0
    sla_violated: bool = False


class TeamDashboardReport(BaseModel):
    team: TeamRead
    total_findings: int = 0
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    sla_violations: int = 0
    findings: list[TeamFindingSummary] = Field(default_factory=list)


# ---------------------------------------------------------------------------
# Integration (Ticketing)
# ---------------------------------------------------------------------------

class IntegrationFieldMappingBase(BaseModel):
    source: str
    target_field: str
    transform: Optional[str] = None
    template_value: Optional[str] = None
    priority: int = 0


class IntegrationFieldMappingCreate(IntegrationFieldMappingBase):
    pass


class IntegrationFieldMappingRead(IntegrationFieldMappingBase):
    id: str
    integration_id: str
    model_config = {"from_attributes": True}


class IntegrationBase(BaseModel):
    name: str
    provider: str
    enabled: bool = True
    base_url: str
    auth_method: str = "api_token"
    provider_config: dict[str, Any] = Field(default_factory=dict)


class IntegrationCreate(IntegrationBase):
    auth_username: Optional[str] = None
    auth_secret: Optional[str] = None
    webhook_secret: Optional[str] = None
    field_mappings: list[IntegrationFieldMappingCreate] = Field(default_factory=list)


class IntegrationUpdate(BaseModel):
    name: Optional[str] = None
    enabled: Optional[bool] = None
    base_url: Optional[str] = None
    auth_method: Optional[str] = None
    auth_username: Optional[str] = None
    auth_secret: Optional[str] = None
    webhook_secret: Optional[str] = None
    provider_config: Optional[dict[str, Any]] = None
    field_mappings: Optional[list[IntegrationFieldMappingCreate]] = None


class IntegrationRead(IntegrationBase):
    id: str
    auth_username: Optional[str] = None
    has_secret: bool = False
    has_webhook_secret: bool = False
    created_at: datetime
    updated_at: datetime
    field_mappings: list[IntegrationFieldMappingRead] = Field(default_factory=list)
    model_config = {"from_attributes": True}


class TicketRead(BaseModel):
    id: str
    integration_id: str
    finding_id: Optional[str] = None
    external_id: str
    external_key: str
    external_url: str
    external_status: Optional[str] = None
    summary: str
    created_at: datetime
    synced_at: Optional[datetime] = None
    external_assignee: Optional[str] = None
    external_priority: Optional[str] = None
    model_config = {"from_attributes": True}


class CreateTicketRequest(BaseModel):
    integration_id: str
    finding_id: str
    field_overrides: dict[str, Any] = Field(default_factory=dict)


class BulkCreateTicketsRequest(BaseModel):
    integration_id: str
    finding_ids: list[str]
    field_overrides: dict[str, Any] = Field(default_factory=dict)
    skip_existing: bool = True


class BulkCreateTicketsResponse(BaseModel):
    created: list[TicketRead]
    skipped: list[str]
    errors: list[dict[str, str]]


class TestIntegrationResponse(BaseModel):
    success: bool
    message: str
    projects: Optional[list[dict[str, str]]] = None


# ---------------------------------------------------------------------------
# Webhook Events
# ---------------------------------------------------------------------------

class WebhookEventRead(BaseModel):
    id: str
    integration_id: str
    event_type: str
    external_issue_id: Optional[str] = None
    external_issue_key: Optional[str] = None
    status: str
    error_message: Optional[str] = None
    received_at: datetime
    processed_at: Optional[datetime] = None

    model_config = {"from_attributes": True}


class WebhookEventDetail(WebhookEventRead):
    payload: dict[str, Any]


# ---------------------------------------------------------------------------
# Webhook Registration
# ---------------------------------------------------------------------------

class WebhookRegistrationCreate(BaseModel):
    callback_url: str
    jira_events: list[str] = Field(default_factory=lambda: [
        "jira:issue_updated",
        "jira:issue_deleted",
        "comment_created",
        "comment_updated",
    ])
    register_with_jira: bool = True  # attempt auto-registration via Jira API
    # Provider-agnostic alternatives (used by GitHub Issues and future providers)
    events: list[str] = Field(default_factory=list)
    register_with_provider: bool = True  # attempt auto-registration with the provider


class WebhookRegistrationRead(BaseModel):
    id: str
    integration_id: str
    external_webhook_id: Optional[str] = None
    callback_url: str
    jira_events: list[str]
    is_cloud: bool
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}


# ---------------------------------------------------------------------------
# Ticket Comments
# ---------------------------------------------------------------------------

class TicketCommentCreate(BaseModel):
    body: str


class TicketCommentRead(BaseModel):
    id: str
    ticket_id: str
    external_comment_id: Optional[str] = None
    author: Optional[str] = None
    body: str
    direction: str
    created_at: datetime

    model_config = {"from_attributes": True}


# ---------------------------------------------------------------------------
# Automation Rules
# ---------------------------------------------------------------------------

class AutomationRuleCreate(BaseModel):
    name: str
    description: Optional[str] = None
    enabled: bool = True
    trigger: str  # e.g. "jira_status_changed", "scan_completed"
    conditions: list[dict[str, Any]] = Field(default_factory=list)
    actions: list[dict[str, Any]] = Field(default_factory=list)
    integration_id: Optional[str] = None
    team_id: Optional[str] = None


class AutomationRuleUpdate(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None
    enabled: Optional[bool] = None
    trigger: Optional[str] = None
    conditions: Optional[list[dict[str, Any]]] = None
    actions: Optional[list[dict[str, Any]]] = None
    integration_id: Optional[str] = None
    team_id: Optional[str] = None


class AutomationRuleRead(BaseModel):
    id: str
    name: str
    description: Optional[str] = None
    enabled: bool
    trigger: str
    conditions: list[dict[str, Any]]
    actions: list[dict[str, Any]]
    integration_id: Optional[str] = None
    team_id: Optional[str] = None
    execution_count: int = 0
    last_executed_at: Optional[datetime] = None
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}


class AutomationRuleExecutionRead(BaseModel):
    id: str
    rule_id: str
    trigger_event: str
    trigger_context: dict[str, Any]
    conditions_matched: bool
    actions_executed: list[dict[str, Any]]
    status: str
    created_at: datetime

    model_config = {"from_attributes": True}
