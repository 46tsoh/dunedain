"""EPSS (Exploit Prediction Scoring System) enrichment service.

Fetches scores from the FIRST.org public API in a single batch request.
API docs: https://www.first.org/epss/api
"""
from __future__ import annotations

import logging
from typing import NamedTuple

import httpx

logger = logging.getLogger(__name__)

_EPSS_API = "https://api.first.org/data/v1/epss"
_TIMEOUT = 15  # seconds
_BATCH_SIZE = 100  # API supports up to ~2000 but 100 is safe


class EpssScore(NamedTuple):
    score: float       # 0.0 u2013 1.0 probability of exploitation in the next 30 days
    percentile: float  # 0.0 u2013 1.0 relative to all scored CVEs


def fetch_epss_scores(cve_ids: list[str]) -> dict[str, EpssScore]:
    """Return EPSS scores for the given CVE IDs.

    Filters out non-CVE identifiers (GHSA-*, etc.) before querying.
    Returns a dict keyed by CVE ID; missing CVEs are simply absent.
    Raises nothing u2014 logs and returns empty dict on any failure.
    """
    # EPSS only covers CVE IDs
    cves = [c for c in cve_ids if c.upper().startswith("CVE-")]
    if not cves:
        return {}

    results: dict[str, EpssScore] = {}

    try:
        with httpx.Client(timeout=_TIMEOUT) as client:
            # Process in batches to stay within URL length limits
            for i in range(0, len(cves), _BATCH_SIZE):
                batch = cves[i : i + _BATCH_SIZE]
                resp = client.get(_EPSS_API, params={"cve": ",".join(batch)})
                resp.raise_for_status()
                data = resp.json()
                for entry in data.get("data", []):
                    cve = entry.get("cve", "")
                    try:
                        score = float(entry["epss"])
                        percentile = float(entry["percentile"])
                        results[cve] = EpssScore(score=score, percentile=percentile)
                    except (KeyError, ValueError, TypeError):
                        logger.warning("Malformed EPSS entry for %s: %s", cve, entry)
    except Exception:
        logger.exception("EPSS fetch failed for %d CVEs", len(cves))

    return results
