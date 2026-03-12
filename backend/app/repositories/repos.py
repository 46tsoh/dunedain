from __future__ import annotations

from collections import defaultdict
from datetime import datetime, timedelta, timezone
from typing import Optional

from sqlalchemy import func
from sqlalchemy.orm import Session

from ..models import AuditLog, Finding, OwnershipRule, Policy, PolicyResult, AppSetting, Registry, Scan, SBOM, Team
from .base import BaseRepository


class ScanRepository(BaseRepository[Scan]):
    model = Scan

    def list_with_filters(
        self,
        *,
        skip: int = 0,
        limit: int = 20,
        scan_type: Optional[str] = None,
        status: Optional[str] = None,
    ) -> list[Scan]:
        filters = []
        if scan_type:
            filters.append(Scan.scan_type == scan_type)
        if status:
            filters.append(Scan.status == status)
        return self.list(skip=skip, limit=limit, order_by=Scan.created_at.desc(), filters=filters or None)

    def delete_all(self) -> int:
        """Delete every scan and all associated data.

        Deletes dependent rows explicitly before the scan rows so SQLite
        foreign-key / cascade constraints are satisfied regardless of whether
        PRAGMA foreign_keys is ON.  Returns the number of scan rows deleted.
        """
        count = self.db.query(Scan).count()
        self.db.query(PolicyResult).delete(synchronize_session=False)
        self.db.query(SBOM).delete(synchronize_session=False)
        self.db.query(Finding).delete(synchronize_session=False)
        self.db.query(Scan).delete(synchronize_session=False)
        self.db.commit()
        return count


class FindingRepository(BaseRepository[Finding]):
    model = Finding

    def for_scan(
        self,
        scan_id: str,
        *,
        severity: Optional[str] = None,
        is_fixed: Optional[bool] = None,
    ) -> list[Finding]:
        filters = [Finding.scan_id == scan_id]
        if severity:
            filters.append(Finding.severity == severity.upper())
        if is_fixed is not None:
            filters.append(Finding.is_fixed == is_fixed)
        return (
            self.db.query(Finding)
            .filter(*filters)
            .order_by(Finding.risk_score.desc())
            .all()
        )

    def severity_counts(self) -> dict[str, int]:
        rows = (
            self.db.query(Finding.severity, func.count(Finding.id))
            .group_by(Finding.severity)
            .all()
        )
        return {sev: cnt for sev, cnt in rows}

    def top_vulnerabilities(self, limit: int = 10) -> list:
        return (
            self.db.query(
                Finding.vulnerability_id,
                Finding.severity,
                func.count(Finding.id).label("cnt"),
                func.max(Finding.cvss_score).label("max_cvss"),
            )
            .group_by(Finding.vulnerability_id, Finding.severity)
            .order_by(func.count(Finding.id).desc())
            .limit(limit)
            .all()
        )

    def trend_since(self, days: int = 30) -> list[Finding]:
        cutoff = datetime.now(timezone.utc) - timedelta(days=days)
        return (
            self.db.query(Finding)
            .join(Scan, Scan.id == Finding.scan_id)
            .filter(Scan.created_at >= cutoff)
            .all()
        )


class PolicyRepository(BaseRepository[Policy]):
    model = Policy

    def list_enabled(self) -> list[Policy]:
        return self.db.query(Policy).filter(Policy.enabled == True).all()  # noqa: E712

    def list_all(self) -> list[Policy]:
        return self.list(order_by=Policy.created_at.desc())


class PolicyResultRepository(BaseRepository[PolicyResult]):
    model = PolicyResult

    def for_scan(self, scan_id: str) -> list[PolicyResult]:
        return (
            self.db.query(PolicyResult)
            .filter(PolicyResult.scan_id == scan_id)
            .all()
        )


class SBOMRepository(BaseRepository[SBOM]):
    model = SBOM

    def for_scan(self, scan_id: str) -> SBOM | None:
        return self.db.query(SBOM).filter(SBOM.scan_id == scan_id).first()


class AuditLogRepository(BaseRepository[AuditLog]):
    model = AuditLog

    def list_with_filters(
        self,
        *,
        skip: int = 0,
        limit: int = 50,
        action: Optional[str] = None,
        resource_type: Optional[str] = None,
    ) -> list[AuditLog]:
        filters = []
        if action:
            filters.append(AuditLog.action == action)
        if resource_type:
            filters.append(AuditLog.resource_type == resource_type)
        return self.list(
            skip=skip,
            limit=limit,
            order_by=AuditLog.created_at.desc(),
            filters=filters or None,
        )


class SettingRepository(BaseRepository[AppSetting]):
    model = AppSetting

    def get_value(self, key: str, default: str = "") -> str:
        row = self.get(key)
        return row.value if row else default

    def set_value(self, key: str, value: str) -> AppSetting:
        row = self.get(key)
        if row is None:
            raise KeyError(key)
        row.value = value
        row.updated_at = datetime.now(timezone.utc)
        self.db.commit()
        self.db.refresh(row)
        return row

    def ensure_defaults(self, defaults: dict[str, tuple[str, str]]) -> None:
        """Seed missing settings rows with (value, description) defaults."""
        for key, (value, description) in defaults.items():
            if not self.get(key):
                self.db.add(AppSetting(
                    key=key,
                    value=value,
                    description=description,
                    updated_at=datetime.now(timezone.utc),
                ))
        self.db.commit()


class RegistryRepository(BaseRepository[Registry]):
    model = Registry

    def list_all(self) -> list[Registry]:
        return self.list(order_by=Registry.created_at.desc())

    def list_auto_sync(self) -> list[Registry]:
        return self.db.query(Registry).filter(Registry.auto_sync.is_(True)).all()

    def get_by_name(self, name: str) -> Registry | None:
        return self.db.query(Registry).filter(Registry.name == name).first()

    def update_cache(
        self,
        registry_id: str,
        repository_cache: dict,
        last_synced_at: datetime,
    ) -> Registry | None:
        reg = self.get(registry_id)
        if not reg:
            return None
        reg.repository_cache = repository_cache
        reg.last_synced_at = last_synced_at
        self.db.commit()
        self.db.refresh(reg)
        return reg


class TeamRepository(BaseRepository[Team]):
    model = Team

    def list_all(self) -> list[Team]:
        return self.list(order_by=Team.created_at.desc())

    def get_by_name(self, name: str) -> Team | None:
        return self.db.query(Team).filter(Team.name == name).first()

    def scans_for_team(self, team_id: str, *, limit: int = 200) -> list[Scan]:
        return (
            self.db.query(Scan)
            .filter(Scan.team_id == team_id)
            .order_by(Scan.created_at.desc())
            .limit(limit)
            .all()
        )


class OwnershipRuleRepository(BaseRepository[OwnershipRule]):
    model = OwnershipRule

    def list_all(self) -> list[OwnershipRule]:
        return self.list(order_by=OwnershipRule.priority.desc())

    def for_team(self, team_id: str) -> list[OwnershipRule]:
        return (
            self.db.query(OwnershipRule)
            .filter(OwnershipRule.team_id == team_id)
            .order_by(OwnershipRule.priority.desc())
            .all()
        )
