from __future__ import annotations

import os

from celery import Celery
from celery.schedules import crontab

BROKER_URL = os.environ.get("CELERY_BROKER_URL", "redis://localhost:6379/0")
RESULT_BACKEND = os.environ.get("CELERY_RESULT_BACKEND", "redis://localhost:6379/0")

celery_app = Celery(
    "dunedain",
    broker=BROKER_URL,
    backend=RESULT_BACKEND,
    include=["app.tasks.scan", "app.tasks.registry_sync", "app.tasks.msrc_refresh", "app.tasks.automation"],
)

celery_app.conf.update(
    task_serializer="json",
    result_serializer="json",
    accept_content=["json"],
    timezone="UTC",
    enable_utc=True,
    task_track_started=True,
    task_acks_late=True,          # only ack after the task completes (safe retries)
    worker_prefetch_multiplier=1, # each worker fetches one task at a time
    task_soft_time_limit=1740,    # send SIGTERM to task after 29 min
    task_time_limit=1800,         # send SIGKILL after 30 min (hard ceiling)
    broker_connection_retry_on_startup=True,
    task_routes={
        "app.tasks.scan.run_scan": {"queue": "scans"},
        "app.tasks.registry_sync.sync_registry": {"queue": "scans"},
        "app.tasks.registry_sync.sync_all_registries": {"queue": "scans"},
        "app.tasks.msrc_refresh.refresh_msrc_cache": {"queue": "scans"},
        "app.tasks.automation.process_webhook_event": {"queue": "scans"},
        "app.tasks.automation.fire_internal_event": {"queue": "scans"},
    },
    beat_schedule={
        "sync-all-registries-every-5-minutes": {
            "task": "app.tasks.registry_sync.sync_all_registries",
            "schedule": crontab(minute="*/5"),
        },
        "refresh-msrc-cache-daily": {
            "task": "app.tasks.msrc_refresh.refresh_msrc_cache",
            "schedule": crontab(hour=3, minute=0),  # 3 AM UTC daily
        },
    },
)
