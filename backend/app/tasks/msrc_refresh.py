"""Celery task: pre-warm the MSRC monthly CVE feed cache.

Runs daily at 3 AM UTC (configured in celery_app.py).  Fetches the current
month and the previous month's CVRF feeds so they are ready on disk before
any Windows scan request arrives.

Failures are logged but do not raise — a stale or missing cache is handled
gracefully by scan_windows_os_cves() at scan time.
"""
from __future__ import annotations

import logging
from datetime import datetime, timezone

from ..celery_app import celery_app
from ..services.msrc import MONTH_ABBRS, _fetch_feed

logger = logging.getLogger(__name__)


@celery_app.task(
    name="app.tasks.msrc_refresh.refresh_msrc_cache",
    bind=False,
    max_retries=0,
    queue="scans",
)
def refresh_msrc_cache() -> None:
    """Fetch and cache the current and previous 2 months of MSRC CVE feeds."""
    now = datetime.now(timezone.utc)
    fetched = 0
    for delta in range(3):  # current month + 2 prior months
        m = now.month - delta
        y = now.year
        if m <= 0:
            m += 12
            y -= 1
        abbr = MONTH_ABBRS[m - 1]
        feed = _fetch_feed(y, abbr)
        if feed is not None:
            cve_count = len(feed.get("Vulnerability", []))
            logger.info("MSRC cache refreshed: %d-%s (%d CVEs)", y, abbr, cve_count)
            fetched += 1
        else:
            logger.warning("MSRC cache refresh failed for %d-%s", y, abbr)

    logger.info("MSRC cache refresh complete: %d/%d feeds fetched", fetched, 3)
