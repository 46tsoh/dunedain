"""Celery tasks for registry synchronisation and auto-scanning new tags."""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from uuid import uuid4

from ..celery_app import celery_app
from ..database import SessionLocal
from ..models import AuditLog, Registry, Scan
from ..repositories import AuditLogRepository, RegistryRepository, ScanRepository
from ..services import registry as registry_svc

logger = logging.getLogger(__name__)


@celery_app.task(
    name="app.tasks.registry_sync.sync_registry",
    bind=True,
    max_retries=2,
    default_retry_delay=60,
    queue="scans",
)
def sync_registry(self, registry_id: str) -> dict:
    """Sync a single registry: refresh repo/tag cache and auto-scan new tags.

    Compares the freshly fetched tag list against what was previously stored in
    ``repository_cache``.  For every *new* tag discovered, a container scan is
    automatically queued.

    Returns a summary dict with counts of repos, new tags, and queued scans.
    """
    db = SessionLocal()
    try:
        reg_repo = RegistryRepository(db)
        scan_repo = ScanRepository(db)
        audit_repo = AuditLogRepository(db)

        reg: Registry | None = reg_repo.get(registry_id)
        if not reg:
            logger.warning("sync_registry called for unknown registry %s", registry_id)
            return {"error": "registry_not_found"}

        logger.info("Syncing registry %s (%s)", reg.name, reg.url)

        # ── Fetch current state from the remote registry ──────────────────
        try:
            new_cache = registry_svc.fetch_full_cache(reg.url, reg.auth_method, username=reg.username, password=reg.password)
        except Exception as exc:
            logger.error("Failed to fetch registry cache for %s: %s", reg.url, exc)
            self.retry(exc=exc)
            return {"error": str(exc)}

        old_cache: dict[str, list[str]] = reg.repository_cache or {}

        # ── Detect new tags ───────────────────────────────────────────────
        new_scans_queued = 0
        for repo, tags in new_cache.items():
            old_tags = set(old_cache.get(repo, []))
            for tag in tags:
                if tag not in old_tags:
                    image_ref = f"{reg.url}/{repo}:{tag}"
                    logger.info("New tag detected: %s — queuing scan", image_ref)

                    # Import here to avoid circular imports at module level
                    from .scan import run_scan
                    from ..services.scanner import _get_scanner_preference
                    scan = scan_repo.add(Scan(
                        id=str(uuid4()),
                        name=image_ref,
                        scan_type="container",
                        target=image_ref,
                        status="pending",
                        registry_id=reg.id,
                        scanner_override=_get_scanner_preference(),
                        created_at=datetime.now(timezone.utc),
                    ))
                    scan_repo.flush()  # get scan.id populated before dispatching
                    run_scan.delay(scan.id)
                    new_scans_queued += 1

        # ── Persist updated cache ─────────────────────────────────────────
        reg_repo.update_cache(reg.id, new_cache, datetime.now(timezone.utc))

        audit_repo.add(AuditLog(
            id=str(uuid4()),
            action="registry_synced",
            resource_type="registry",
            resource_id=reg.id,
            details={
                "registry_name": reg.name,
                "repositories": len(new_cache),
                "new_scans_queued": new_scans_queued,
            },
        ))
        audit_repo.commit()

        logger.info(
            "Registry %s synced: %d repos, %d new scans queued",
            reg.name, len(new_cache), new_scans_queued,
        )
        return {
            "registry_id": registry_id,
            "repositories": len(new_cache),
            "new_scans_queued": new_scans_queued,
        }

    finally:
        db.close()


@celery_app.task(
    name="app.tasks.registry_sync.sync_all_registries",
    queue="scans",
)
def sync_all_registries() -> dict:
    """Beat-scheduled task: iterate all registries and dispatch sync_registry for each.

    This is the entry-point called by Celery beat every N minutes.
    """
    db = SessionLocal()
    try:
        registries = RegistryRepository(db).list_auto_sync()
        dispatched = 0
        for reg in registries:
            sync_registry.delay(reg.id)
            dispatched += 1
        logger.info("sync_all_registries: dispatched %d registry syncs", dispatched)
        return {"dispatched": dispatched}
    finally:
        db.close()
