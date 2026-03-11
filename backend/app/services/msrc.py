"""Microsoft Security Response Center (MSRC) CVRF integration.

Fetches monthly security update feeds from the MSRC CVRF API v3.0 and
matches Windows OS CVEs against the build version detected in a container
image's PE artifacts.

Matching strategy
-----------------
Syft's ``dotnet-portable-executable-cataloger`` extracts ``productVersion``
from every .dll/.exe in the image layers.  For Microsoft OS DLLs these look
like ``10.0.20348.4648``.  The four-part version encodes:

    10.0 . <baseline> . <revision>

where ``baseline`` identifies the Windows release:

    14393  → Windows Server 2016 / Windows 10 1607
    17763  → Windows Server 2019 / Windows 10 1809
    20348  → Windows Server 2022
    22000  → Windows 11 21H2
    22621  → Windows 11 22H2 / Server 2022 23H2
    22631  → Windows 11 23H2
    26100  → Windows 11 24H2 / Windows Server 2025

``revision`` is the cumulative-update patch level.  Each monthly Patch
Tuesday bumps it.  A CVE entry in the CVRF feed carries a ``FixedBuild``
value like ``10.0.20348.4773``.  If ``image_revision < fixed_revision`` the
image is missing the patch and is vulnerable.

MSRC API
--------
Base URL: https://api.msrc.microsoft.com/cvrf/v3.0/
No API key required for JSON responses (use ``Accept: application/json``).
Monthly feeds: GET /cvrf/{YYYY-Mmm}  (e.g. ``2026-Feb``)
Updates index: GET /updates

Caching
-------
Feeds are cached on disk under ``/data/msrc-cache/`` (the same shared volume
used by everything else) as ``{year}-{mon}.json``.  A feed is re-fetched at
most once per day.  The last 24 months of data are kept.
"""
from __future__ import annotations

import json
import logging
import os
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import httpx

logger = logging.getLogger(__name__)

MSRC_BASE = "https://api.msrc.microsoft.com/cvrf/v3.0"
CACHE_DIR = Path(os.environ.get("MSRC_CACHE_DIR", "/data/msrc-cache"))
CACHE_TTL_SECONDS = 86400  # re-fetch a feed at most once per day

# ---------------------------------------------------------------------------
# Baseline build → Windows product IDs (amd64 only; containers are amd64)
# These are stable IDs from the MSRC product tree — add new releases here.
# ---------------------------------------------------------------------------
BASELINE_PRODUCT_IDS: dict[int, list[str]] = {
    14393: ["10816", "10855"],          # Server 2016 / Win10 1607
    17763: ["11571", "11572"],          # Server 2019 / Win10 1809
    20348: ["11923", "11924"],          # Server 2022
    22000: ["11929", "11930", "11931"], # Win11 21H2 (also Win10 21H2 overlap)
    22621: ["12097", "12098", "12099", "12242", "12243", "12244"],  # Win11 22H2 / Server 2022 23H2
    22631: ["12242", "12243"],          # Win11 23H2
    26100: ["12389", "12390", "12436", "12437"],  # Win11 24H2 / Server 2025
}

# Human-readable names for UI display
BASELINE_NAMES: dict[int, str] = {
    14393: "Windows Server 2016",
    17763: "Windows Server 2019",
    20348: "Windows Server 2022",
    22000: "Windows 11 21H2",
    22621: "Windows 11 22H2 / Server 2022 23H2",
    22631: "Windows 11 23H2",
    26100: "Windows 11 24H2 / Windows Server 2025",
}

SEVERITY_MAP = {9.0: "CRITICAL", 7.0: "HIGH", 4.0: "MEDIUM", 0.1: "LOW"}


# ---------------------------------------------------------------------------
# Version helpers
# ---------------------------------------------------------------------------

def _parse_build(version_str: str) -> tuple[int, int] | None:
    """Parse ``10.0.BASELINE.REVISION`` → ``(baseline, revision)``.

    Returns ``None`` for anything that doesn't match the pattern.
    """
    parts = version_str.split(".")
    if len(parts) != 4:
        return None
    try:
        if int(parts[0]) != 10 or int(parts[1]) != 0:
            return None
        return int(parts[2]), int(parts[3])
    except ValueError:
        return None


def extract_windows_build(syft_artifacts: list[dict]) -> tuple[int, int] | None:
    """Return the highest ``(baseline, revision)`` found in Syft PE artifacts.

    Iterates over all artifacts, skips non-Microsoft DLLs, and returns the
    max revision for the most common baseline (voting by count, to avoid
    being fooled by a single anomalous DLL).
    """
    from collections import Counter, defaultdict

    baseline_revisions: dict[int, list[int]] = defaultdict(list)

    for art in syft_artifacts:
        meta = art.get("metadata", {})
        company = meta.get("companyName", "")
        if "Microsoft" not in company:
            continue
        pv = meta.get("productVersion", "")
        parsed = _parse_build(pv)
        if not parsed:
            continue
        baseline, revision = parsed
        if baseline in BASELINE_PRODUCT_IDS:
            baseline_revisions[baseline].append(revision)

    if not baseline_revisions:
        return None

    # Pick the baseline with the most DLLs (most representative)
    baseline = max(baseline_revisions, key=lambda b: len(baseline_revisions[b]))
    # Use the highest revision seen (most recently updated DLL in the image)
    revision = max(baseline_revisions[baseline])
    return baseline, revision


# ---------------------------------------------------------------------------
# MSRC feed fetching + caching
# ---------------------------------------------------------------------------

def _cache_path(year: int, month_abbr: str) -> Path:
    CACHE_DIR.mkdir(parents=True, exist_ok=True)
    return CACHE_DIR / f"{year}-{month_abbr}.json"


def _fetch_feed(year: int, month_abbr: str) -> dict | None:
    """Fetch a single monthly CVRF feed, using disk cache when fresh."""
    path = _cache_path(year, month_abbr)
    if path.exists():
        age = time.time() - path.stat().st_mtime
        if age < CACHE_TTL_SECONDS:
            try:
                return json.loads(path.read_text())
            except (json.JSONDecodeError, OSError):
                pass  # corrupt cache — re-fetch

    url = f"{MSRC_BASE}/cvrf/{year}-{month_abbr}"
    try:
        with httpx.Client(timeout=30) as client:
            r = client.get(url, headers={"Accept": "application/json"})
        if r.status_code != 200:
            return None
        data = r.json()
        path.write_text(json.dumps(data))
        return data
    except Exception as exc:
        logger.warning("MSRC fetch failed for %s-%s: %s", year, month_abbr, exc)
        return None


MONTH_ABBRS = ["Jan", "Feb", "Mar", "Apr", "May", "Jun",
               "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"]


def _months_since(baseline_year: int, baseline_month: int, lookback: int = 24) -> list[tuple[int, str]]:
    """Return up to ``lookback`` (year, month_abbr) tuples in reverse-chron order."""
    now = datetime.now(timezone.utc)
    results = []
    y, m = now.year, now.month
    for _ in range(lookback):
        if (y, m) >= (baseline_year, baseline_month):
            results.append((y, MONTH_ABBRS[m - 1]))
        m -= 1
        if m == 0:
            m = 12
            y -= 1
    return results


# ---------------------------------------------------------------------------
# CVE matching
# ---------------------------------------------------------------------------

def _cvss_to_severity(score: float | None) -> str:
    if score is None:
        return "UNKNOWN"
    for threshold, sev in sorted(SEVERITY_MAP.items(), reverse=True):
        if score >= threshold:
            return sev
    return "UNKNOWN"


def _extract_cves_from_feed(
    feed: dict,
    product_ids: set[str],
    image_baseline: int,
    image_revision: int,
) -> list[dict[str, Any]]:
    """Extract vulnerable CVE findings from a single CVRF feed document."""
    findings = []
    for vuln in feed.get("Vulnerability", []):
        cve_id = vuln.get("CVE", "")
        if not cve_id:
            continue

        # Title and Description can be either {"Value": "..."} or a plain string
        title_raw = vuln.get("Title", "")
        title = title_raw.get("Value", "") if isinstance(title_raw, dict) else (title_raw or "")
        threat_desc = ""
        for threat in vuln.get("Threats", []):
            if threat.get("Type") == 0:  # Description
                desc_raw = threat.get("Description", "")
                threat_desc = desc_raw.get("Value", "") if isinstance(desc_raw, dict) else (desc_raw or "")
                break

        # CVSS
        cvss_score = None
        for cs in vuln.get("CVSSScoreSets", []):
            s = cs.get("BaseScore")
            if s is not None:
                try:
                    s = float(s)
                    if cvss_score is None or s > cvss_score:
                        cvss_score = s
                except (TypeError, ValueError):
                    pass

        # Check remediations for matching product + FixedBuild
        matched = False
        fixed_build_str = None
        for r in vuln.get("Remediations", []):
            pids = set(r.get("ProductID", []))
            fb = r.get("FixedBuild", "")
            if not (pids & product_ids) or not fb:
                continue
            parsed = _parse_build(fb)
            if not parsed:
                continue
            fixed_baseline, fixed_revision = parsed
            if fixed_baseline != image_baseline:
                continue
            # Vulnerable if image revision is strictly less than the fixed revision
            if image_revision < fixed_revision:
                matched = True
                fixed_build_str = fb
                break

        if not matched:
            continue

        severity = _cvss_to_severity(cvss_score)

        # Check for KEV (Known Exploited Vulnerabilities) flag
        exploitable = False
        for threat in vuln.get("Threats", []):
            if threat.get("Type") == 1:  # Exploit status
                kev_raw = threat.get("Description", "")
                val = kev_raw.get("Value", "") if isinstance(kev_raw, dict) else (kev_raw or "")
                if "exploited" in val.lower() or "kev" in val.lower():
                    exploitable = True
                    break

        findings.append({
            "vulnerability_id": cve_id,
            "package_name": f"Windows OS (build 10.0.{image_baseline}.{image_revision})",
            "package_version": f"10.0.{image_baseline}.{image_revision}",
            "package_ecosystem": "windows-os",
            "severity": severity,
            "cvss_score": cvss_score,
            "description": title or threat_desc,
            "fix_version": fixed_build_str,
            "is_fixed": True,  # a patch exists
            "reachable": False,
            "exploitable": exploitable,
            "references": [
                f"https://msrc.microsoft.com/update-guide/vulnerability/{cve_id}"
            ],
        })

    return findings


def _scan_msrc_for_build(
    baseline: int,
    revision: int,
    lookback_months: int = 24,
) -> list[dict[str, Any]]:
    """Fetch MSRC monthly feeds and return CVE findings for the given build.

    Shared by both PE-based and registry-hive-based Windows scanning paths.
    Returns an empty list when the baseline is unknown or all feeds fail.
    """
    product_ids = set(BASELINE_PRODUCT_IDS.get(baseline, []))
    if not product_ids:
        logger.debug("Baseline %d not in product ID map — skipping MSRC scan", baseline)
        return []

    os_name = BASELINE_NAMES.get(baseline, f"Windows (build {baseline})")
    logger.info(
        "MSRC scan: %s build 10.0.%d.%d, matching against product IDs %s",
        os_name, baseline, revision, product_ids,
    )

    baseline_release = {
        14393: (2016, 8),
        17763: (2018, 10),
        20348: (2021, 10),
        22000: (2021, 10),
        22621: (2022, 9),
        22631: (2023, 10),
        26100: (2024, 6),
    }
    rel_year, rel_month = baseline_release.get(baseline, (2021, 1))
    months = _months_since(rel_year, rel_month, lookback=lookback_months)

    all_findings: list[dict] = []
    seen_cves: set[str] = set()

    for year, month_abbr in months:
        feed = _fetch_feed(year, month_abbr)
        if feed is None:
            continue
        feed_findings = _extract_cves_from_feed(feed, product_ids, baseline, revision)
        for f in feed_findings:
            cve = f["vulnerability_id"]
            if cve not in seen_cves:
                seen_cves.add(cve)
                all_findings.append(f)

    logger.info("MSRC scan complete: %d OS CVEs found for %s", len(all_findings), os_name)
    return all_findings


def extract_windows_build_from_registry(extracted_path: Path) -> tuple[int, int] | None:
    """Parse the Windows SOFTWARE registry hive from an extracted container filesystem.

    Reads ``HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion`` to obtain:
      - ``CurrentBuildNumber`` → baseline (e.g. ``20348`` for Server 2022)
      - ``UBR`` (Update Build Revision) → cumulative update revision

    Checks the OCI layer convention path first
    (``Files/Windows/System32/config/SOFTWARE``), then the ``Hives/`` directory
    convention used by some Windows images (``Hives/Software``).

    Returns ``(baseline, revision)`` on success, ``None`` on any failure
    (hive absent, regipy not installed, key missing, unknown baseline).
    """
    try:
        from regipy.registry import RegistryHive
    except ImportError:
        logger.warning("regipy is not installed; cannot parse Windows registry hive")
        return None

    hive_candidates = [
        extracted_path / "Files" / "Windows" / "System32" / "config" / "SOFTWARE",
        extracted_path / "Hives" / "Software",
        extracted_path / "Windows" / "System32" / "config" / "SOFTWARE",
    ]
    hive_path = next((p for p in hive_candidates if p.exists()), None)
    if hive_path is None:
        logger.debug("SOFTWARE hive not found under %s", extracted_path)
        return None

    try:
        hive = RegistryHive(str(hive_path))
        key = hive.get_key(r"Microsoft\Windows NT\CurrentVersion")
        values = {v.name: v.value for v in key.get_values()}
        build_str = str(values.get("CurrentBuildNumber", ""))
        ubr = values.get("UBR")
        if not build_str or ubr is None:
            logger.debug("CurrentBuildNumber or UBR missing from registry hive")
            return None
        baseline = int(build_str)
        revision = int(ubr)
        if baseline not in BASELINE_PRODUCT_IDS:
            logger.debug("Registry baseline %d not in product ID map", baseline)
            return None
        logger.info(
            "Registry hive: detected %s build 10.0.%d.%d",
            BASELINE_NAMES.get(baseline, f"Windows (build {baseline})"),
            baseline,
            revision,
        )
        return baseline, revision
    except Exception as exc:
        logger.warning("Failed to parse SOFTWARE hive at %s: %s", hive_path, exc)
        return None


def scan_windows_os_cves(
    syft_artifacts: list[dict],
    lookback_months: int = 24,
) -> list[dict[str, Any]]:
    """Match Windows OS CVEs against the build version in Syft PE artifacts.

    Fetches MSRC monthly feeds (cached) and returns findings for all CVEs
    where the image's cumulative update revision is older than the fix.

    Returns an empty list (not an error) when:
    - No Microsoft PE artifacts are found (non-Windows image or nanoserver)
    - The detected baseline is not in our product ID map
    - All MSRC feeds fail to fetch (network unavailable)
    """
    result = extract_windows_build(syft_artifacts)
    if result is None:
        logger.debug("No Windows baseline build detected in Syft artifacts")
        return []

    baseline, revision = result
    return _scan_msrc_for_build(baseline, revision, lookback_months)
