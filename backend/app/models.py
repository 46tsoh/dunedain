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
    risk_score = Column(Float, default=0.0, nullable=False)
    aliases = Column(JSON, default=list)
    references = Column(JSON, default=list)

    scan = relationship("Scan", back_populates="findings")


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

    ownership_rules = relationship("OwnershipRule", back_populates="team", cascade="all, delete-orphan")
    scans = relationship("Scan", back_populates="team")


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
