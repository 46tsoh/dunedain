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
        Enum("acr", "docker_hub", "ghcr", "generic", name="registry_type_enum"),
        nullable=False,
        default="acr",
    )
    auth_method = Column(
        Enum("managed_identity", "username_password", "none", name="registry_auth_enum"),
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
    scan_type = Column(Enum("container", "dependency", "source", name="scan_type_enum"), nullable=False)
    target = Column(String, nullable=False)
    status = Column(
        Enum("pending", "running", "completed", "failed", "unsupported", name="scan_status_enum"),
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

    findings = relationship("Finding", back_populates="scan", cascade="all, delete-orphan")
    sbom = relationship("SBOM", back_populates="scan", uselist=False, cascade="all, delete-orphan")
    policy_results = relationship("PolicyResult", back_populates="scan", cascade="all, delete-orphan")
    registry = relationship("Registry", back_populates="scans")


class Finding(Base):
    __tablename__ = "findings"

    id = Column(String, primary_key=True, default=_uuid)
    scan_id = Column(String, ForeignKey("scans.id"), nullable=False)

    package_name = Column(String, nullable=False)
    package_version = Column(String, nullable=False)
    package_ecosystem = Column(String, nullable=False)

    vulnerability_id = Column(String, nullable=False)
    severity = Column(
        Enum("CRITICAL", "HIGH", "MEDIUM", "LOW", "NEGLIGIBLE", "UNKNOWN", name="severity_enum"),
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
        Enum("block", "warn", "audit", name="policy_action_enum"),
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
    format = Column(Enum("cyclonedx", "spdx", name="sbom_format_enum"), nullable=False, default="cyclonedx")
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


class AppSetting(Base):
    __tablename__ = "app_settings"

    key = Column(String, primary_key=True)
    value = Column(String, nullable=False)
    description = Column(String, nullable=True)
    updated_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc), nullable=False)
