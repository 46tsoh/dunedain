from __future__ import annotations

import json
import re
import shutil
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from uuid import uuid4

import httpx

from .risk import compute_risk_score
from ..database import SessionLocal

class WindowsImageUnsupportedError(Exception):
    """Raised when a Windows container image cannot be scanned at all.

    This is only raised as a last resort — after Grype has been attempted and
    also failed.  Grype is the best available OSS tool for Windows images: it
    detects language packages (.NET/NuGet, Node, Java, Python, etc.) and
    binary-matched CVEs (7-Zip, SQLite, OpenSSL, etc.) from PE version
    resources, even from a Linux host.

    What Grype cannot cover without a custom MSRC-backed database:
      - Windows OS KB patch-level CVEs (requires Microsoft CVRF API key +
        custom grype-db build).

    Future work: integrate the MSRC CVRF API to add KB-level CVE matching on
    top of the Grype binary/language results.
    """


def _detect_image_platform(image_name: str) -> str:
    """Return the platform string to pass to scanners for a given image.

    Attempts to fetch the OCI/Docker manifest index from the registry.  If the
    index contains only Windows manifests (no linux/amd64 entry) we return
    ``"windows/amd64"`` so scanners know to request the Windows layer.
    Returns ``"linux/amd64"`` (the default) in all other cases, including when
    the manifest cannot be fetched (network error, private registry, etc.).

    This avoids the hard failure:
        "no child with platform linux/amd64 in index"
    that both Trivy and Grype raise for Windows-only images when no --platform
    flag is given.
    """
    # Normalise image reference into (registry_host, repository, tag/digest)
    # e.g. "mcr.microsoft.com/windows/nanoserver:ltsc2022"
    #      "nginx:latest"           → index.docker.io / library/nginx / latest
    #      "ghcr.io/owner/repo:v1"  → ghcr.io / owner/repo / v1
    ref = image_name
    tag = "latest"
    if "@" in ref.split("/")[-1]:
        ref, digest = ref.rsplit("@", 1)
        tag = digest
    elif ":" in ref.split("/")[-1]:
        ref, tag = ref.rsplit(":", 1)

    parts = ref.split("/")
    if len(parts) == 1 or ("." not in parts[0] and ":" not in parts[0] and parts[0] != "localhost"):
        # No explicit registry host — Docker Hub
        host = "registry-1.docker.io"
        repo = f"library/{ref}" if len(parts) == 1 else ref
    else:
        host = parts[0]
        repo = "/".join(parts[1:])

    # Resolve a Bearer token anonymously for the manifest read
    token: str | None = None
    try:
        auth_challenge: dict[str, str] = {}
        with httpx.Client(timeout=8) as client:
            r = client.get(
                f"https://{host}/v2/",
                headers={"Accept": "application/json"},
            )
            if r.status_code == 401:
                www = r.headers.get("www-authenticate", "")
                if www.lower().startswith("bearer "):
                    import re as _re
                    for m in _re.finditer(r'(\w+)="([^"]*)"', www[7:]):
                        auth_challenge[m.group(1)] = m.group(2)
        realm = auth_challenge.get("realm")
        if realm:
            params: dict[str, str] = {"service": auth_challenge.get("service", host),
                                       "scope": f"repository:{repo}:pull"}
            with httpx.Client(timeout=8) as client:
                tr = client.get(realm, params=params)
                if tr.status_code == 200:
                    token = tr.json().get("token") or tr.json().get("access_token")
    except Exception:
        pass

    headers: dict[str, str] = {
        "Accept": (
            "application/vnd.oci.image.index.v1+json,"
            "application/vnd.docker.distribution.manifest.list.v2+json,"
            "application/vnd.docker.distribution.manifest.v2+json"
        )
    }
    if token:
        headers["Authorization"] = f"Bearer {token}"

    try:
        with httpx.Client(timeout=10) as client:
            r = client.get(
                f"https://{host}/v2/{repo}/manifests/{tag}",
                headers=headers,
            )
        if r.status_code != 200:
            return "linux/amd64"
        manifest = r.json()
    except Exception:
        return "linux/amd64"

    media_type = manifest.get("mediaType", "")
    # Multi-platform index
    if "index" in media_type or "manifest.list" in media_type or "manifests" in manifest:
        manifests = manifest.get("manifests", [])
        has_linux = any(
            m.get("platform", {}).get("os", "linux").lower() == "linux"
            for m in manifests
        )
        if not has_linux and manifests:
            # All entries are non-linux — check if they're windows
            first_os = manifests[0].get("platform", {}).get("os", "").lower()
            if first_os == "windows":
                return "windows/amd64"
        return "linux/amd64"

    # Single-platform manifest — check the config os field
    config_os = manifest.get("os", "linux").lower()
    if config_os == "windows":
        return "windows/amd64"

    return "linux/amd64"


def _get_scanner_preference() -> str:
    """Return the scanner_backend setting value from the DB.

    Falls back to 'auto' if the DB is unreachable or the row doesn't exist yet.
    Values: 'auto' | 'trivy' | 'grype' | 'syft_grype'
    """
    try:
        db = SessionLocal()
        try:
            from ..models import AppSetting
            row = db.get(AppSetting, "scanner_backend")
            return row.value.lower() if row else "auto"
        finally:
            db.close()
    except Exception:
        return "auto"


def _get_comparison_backend() -> str:
    """Return the comparison_backend setting value from the DB.

    Returns 'none' if unset, meaning no comparison scan should be dispatched.
    Values: 'none' | 'auto' | 'trivy' | 'grype' | 'syft_grype'
    """
    try:
        db = SessionLocal()
        try:
            from ..models import AppSetting
            row = db.get(AppSetting, "comparison_backend")
            return row.value.lower() if row else "none"
        finally:
            db.close()
    except Exception:
        return "none"


def _get_windows_scanner_mode() -> str:
    """Return the windows_scanner_mode setting value from the DB.

    Falls back to 'pe_version' if the DB is unreachable or the row doesn't exist.
    Values: 'pe_version' | 'layer_extraction'
    """
    try:
        db = SessionLocal()
        try:
            from ..models import AppSetting
            row = db.get(AppSetting, "windows_scanner_mode")
            return row.value.lower() if row else "pe_version"
        finally:
            db.close()
    except Exception:
        return "pe_version"


def _get_windows_scanner_backend() -> str:
    """Return the windows_scanner_backend setting value from the DB.

    Falls back to 'grype' if the DB is unreachable or the row doesn't exist.
    Values: 'grype' | 'trivy'
    """
    try:
        db = SessionLocal()
        try:
            from ..models import AppSetting
            row = db.get(AppSetting, "windows_scanner_backend")
            return row.value.lower() if row else "grype"
        finally:
            db.close()
    except Exception:
        return "grype"

# ---------------------------------------------------------------------------
# Trivy integration helpers
# ---------------------------------------------------------------------------

# Maps Trivy language-package type names to OSV ecosystem names.
# OS-level package types (debian, alpine, …) are intentionally omitted because
# their naming conventions differ from OSV; Trivy findings for those are used
# as-is without a secondary OSV lookup.
_TRIVY_LANG_TO_OSV_ECOSYSTEM: dict[str, str] = {
    "python-pkg": "PyPI",
    "node-pkg": "npm",
    "go": "Go",
    "cargo": "crates.io",
    "jar": "Maven",
    "pom": "Maven",
    "gem": "RubyGems",
    "composer": "Packagist",
    "nuget": "NuGet",
    "pub": "Pub",
    "hex": "Hex",
}


def _run_trivy_json(
    target: str,
    scan_type: str = "image",
    username: str | None = None,
    password: str | None = None,
    platform: str | None = None,
) -> dict | None:
    """Invoke Trivy and return its parsed JSON output.

    Returns ``None`` if Trivy is not installed, the scan fails, or the output
    cannot be parsed.  ``scan_type`` maps to Trivy sub-commands: ``"image"``
    for container images and ``"fs"`` for local filesystem paths.

    Each call uses a process-scoped cache directory to avoid lock contention
    when multiple Celery workers run Trivy simultaneously.

    ``username`` / ``password`` are forwarded as ``--username`` / ``--password``
    flags when provided (used for authenticated registry pulls).
    """
    if not shutil.which("trivy"):
        return None
    import os
    # Isolate the Trivy cache per-process so concurrent workers don't contend
    # on the same BoltDB lock.
    cache_dir = f"/tmp/trivy-cache-{os.getpid()}"
    cmd = [
        "trivy",
        scan_type,
        "--format", "json",
        "--quiet",
        "--exit-code", "0",
        "--cache-dir", cache_dir,
    ]
    if platform:
        cmd += ["--platform", platform]
    if username:
        cmd += ["--username", username]
    if password:
        cmd += ["--password", password]
    cmd.append(target)
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=1800,
        )
        if not result.stdout.strip():
            return None
        return json.loads(result.stdout)
    except (subprocess.TimeoutExpired, subprocess.SubprocessError, json.JSONDecodeError, OSError):
        return None


def _trivy_results_to_findings(trivy_json: dict) -> list[dict[str, Any]]:
    """Convert Trivy JSON vulnerability results to the internal finding dict format."""
    findings: list[dict[str, Any]] = []

    for result in trivy_json.get("Results", []):
        trivy_type = result.get("Type", "").lower()
        # Use the OSV ecosystem name when available; fall back to the raw Trivy type.
        ecosystem = _TRIVY_LANG_TO_OSV_ECOSYSTEM.get(trivy_type, trivy_type)

        for vuln in result.get("Vulnerabilities", []) or []:
            severity = vuln.get("Severity", "UNKNOWN").upper()
            if severity not in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "NEGLIGIBLE"):
                severity = "UNKNOWN"

            # Take the highest CVSS score available across all sources.
            cvss_score: float | None = None
            for source_data in vuln.get("CVSS", {}).values():
                for score_key in ("V3Score", "V2Score"):
                    score = source_data.get(score_key)
                    if isinstance(score, (int, float)):
                        val = float(score)
                        if cvss_score is None or val > cvss_score:
                            cvss_score = val

            fix_version = vuln.get("FixedVersion") or None
            refs = [r for r in vuln.get("References", []) if isinstance(r, str) and r]

            findings.append(
                {
                    "id": str(uuid4()),
                    "package_name": vuln.get("PkgName", "unknown"),
                    "package_version": vuln.get("InstalledVersion", "unknown"),
                    "package_ecosystem": ecosystem,
                    "vulnerability_id": vuln.get("VulnerabilityID", "UNKNOWN"),
                    "severity": severity,
                    "cvss_score": cvss_score,
                    "description": (vuln.get("Title") or vuln.get("Description") or "")[:500],
                    "fix_version": fix_version,
                    "is_fixed": bool(fix_version),
                    "reachable": False,
                    "exploitable": False,
                    "risk_score": compute_risk_score(cvss_score, severity, False, False),
                    "aliases": [],
                    "references": refs,
                }
            )

    return findings


# ---------------------------------------------------------------------------
# Grype integration helpers (alternative OSS scanner by Anchore)
# https://github.com/anchore/grype
# ---------------------------------------------------------------------------

# Maps Grype artifact types to OSV ecosystem names.
# OS-level types (rpm, deb, apk, …) are intentionally omitted; their naming
# conventions are incompatible with OSV's batch query format.
_GRYPE_LANG_TO_OSV_ECOSYSTEM: dict[str, str] = {
    "python": "PyPI",
    "javascript": "npm",
    "go-module": "Go",
    "rust-crate": "crates.io",
    "java-archive": "Maven",
    "ruby-gem": "RubyGems",
    "dotnet": "NuGet",
    "dart-pub": "Pub",
    "elixir-mix": "Hex",
    "swift": "SwiftURL",
    "cocoapod": "CocoaPods",
}


def _run_grype_json(
    target: str,
    username: str | None = None,
    password: str | None = None,
) -> dict | None:
    """Invoke Grype and return its parsed JSON output.

    Returns ``None`` if Grype is not installed, the scan fails, or the output
    cannot be parsed.  Use ``"dir:/path"`` for filesystem scans and a plain
    image name (e.g. ``"nginx:latest"``) for container image scans.

    ``username`` / ``password`` are injected as ``GRYPE_REGISTRY_AUTH_*``
    environment variables when provided.
    """
    if not shutil.which("grype"):
        return None
    import os
    env = os.environ.copy()
    if username:
        env["GRYPE_REGISTRY_AUTH_USERNAME"] = username
    if password:
        env["GRYPE_REGISTRY_AUTH_PASSWORD"] = password
    cmd = [
        "grype",
        target,
        "--output", "json",
        "--quiet",
        "--add-cpes-if-none",
    ]
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=1800,
            env=env,
        )
        if not result.stdout.strip():
            return None
        return json.loads(result.stdout)
    except (subprocess.TimeoutExpired, subprocess.SubprocessError, json.JSONDecodeError, OSError):
        return None


def _grype_results_to_findings(grype_json: dict) -> list[dict[str, Any]]:
    """Convert Grype JSON match results to the internal finding dict format."""
    findings: list[dict[str, Any]] = []

    for match in grype_json.get("matches", []):
        vuln = match.get("vulnerability", {})
        artifact = match.get("artifact", {})

        severity = vuln.get("severity", "Unknown").upper()
        # Grype emits "Negligible" for vulnerabilities below the LOW threshold.
        if severity not in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "NEGLIGIBLE"):
            severity = "UNKNOWN"

        # Take the highest CVSS base score across all entries.
        cvss_score: float | None = None
        for cvss_entry in vuln.get("cvss", []):
            score = cvss_entry.get("metrics", {}).get("baseScore")
            if isinstance(score, (int, float)):
                val = float(score)
                if cvss_score is None or val > cvss_score:
                    cvss_score = val

        fix_info = vuln.get("fix", {})
        fix_versions: list[str] = fix_info.get("versions", []) or []
        fix_version = fix_versions[0] if fix_versions else None
        is_fixed = fix_info.get("state", "") == "fixed" and bool(fix_version)

        artifact_type = artifact.get("type", "").lower()
        ecosystem = _GRYPE_LANG_TO_OSV_ECOSYSTEM.get(artifact_type, artifact_type)

        refs = [u for u in vuln.get("urls", []) if isinstance(u, str) and u]

        findings.append(
            {
                "id": str(uuid4()),
                "package_name": artifact.get("name", "unknown"),
                "package_version": artifact.get("version", "unknown"),
                "package_ecosystem": ecosystem,
                "vulnerability_id": vuln.get("id", "UNKNOWN"),
                "severity": severity,
                "cvss_score": cvss_score,
                "description": vuln.get("description", "")[:500],
                "fix_version": fix_version,
                "is_fixed": is_fixed,
                "reachable": False,
                "exploitable": False,
                "risk_score": compute_risk_score(cvss_score, severity, False, False),
                "aliases": [],
                "references": refs,
            }
        )

    return findings


# ---------------------------------------------------------------------------
# Syft integration helpers (SBOM generator by Anchore)
# https://github.com/anchore/syft
# ---------------------------------------------------------------------------

def _run_syft_sbom(
    target: str,
    username: str | None = None,
    password: str | None = None,
    platform: str | None = None,
) -> str | None:
    """Run Syft against a registry image and return a CycloneDX JSON SBOM string.

    Uses ``registry:`` prefix so Syft fetches only the manifest + needed layers
    directly from the registry API — no full image pull required.

    ``username`` / ``password`` are injected as ``SYFT_REGISTRY_AUTH_*``
    environment variables when provided.

    Returns ``None`` if Syft is not installed, the scan fails, or no output is
    produced.
    """
    if not shutil.which("syft"):
        return None
    import os
    # Normalise target: strip any leading "registry:" to avoid double-prefix
    bare = target.removeprefix("registry:")
    env = os.environ.copy()
    if username:
        env["SYFT_REGISTRY_AUTH_USERNAME"] = username
    if password:
        env["SYFT_REGISTRY_AUTH_PASSWORD"] = password
    if username or password:
        # Syft requires SYFT_REGISTRY_AUTH_AUTHORITY to bind credentials to a
        # specific registry host.  Without it the username/password env vars are
        # ignored and anonymous rate-limits apply.
        # Derive the authority from the image reference:
        #   - "index.docker.io/library/nginx:latest" → "index.docker.io"
        #   - "myregistry.azurecr.io/repo:tag"       → "myregistry.azurecr.io"
        #   - "nginx:latest" (no host component)      → "index.docker.io"
        parts = bare.split("/")
        # A hostname contains a dot or colon (port); plain names like "nginx" don't.
        if len(parts) > 1 and ("." in parts[0] or ":" in parts[0]):
            authority = parts[0]
        else:
            authority = "index.docker.io"
        env["SYFT_REGISTRY_AUTH_AUTHORITY"] = authority
    try:
        cmd = [
            "syft",
            f"registry:{bare}",
            "--output", "cyclonedx-json",
            # Omit --quiet so errors appear in worker stderr/logs
        ]
        if platform:
            cmd += ["--platform", platform]
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=1800,
            env=env,
        )
        if not result.stdout.strip():
            return None
        return result.stdout
    except (subprocess.TimeoutExpired, subprocess.SubprocessError, OSError):
        return None


def _run_syft_json(
    target: str,
    username: str | None = None,
    password: str | None = None,
    platform: str | None = None,
) -> dict | None:
    """Run Syft and return parsed native JSON output (``syft-json`` format).

    Used to obtain the full artifact list including ``metadata.productVersion``
    fields from PE binaries — required for MSRC build-version matching.
    The CycloneDX format strips this metadata, so we need the native format.

    Returns ``None`` on any failure.
    """
    if not shutil.which("syft"):
        return None
    import os
    bare = target.removeprefix("registry:")
    env = os.environ.copy()
    if username:
        env["SYFT_REGISTRY_AUTH_USERNAME"] = username
    if password:
        env["SYFT_REGISTRY_AUTH_PASSWORD"] = password
    if username or password:
        parts = bare.split("/")
        authority = parts[0] if len(parts) > 1 and ("." in parts[0] or ":" in parts[0]) else "index.docker.io"
        env["SYFT_REGISTRY_AUTH_AUTHORITY"] = authority
    try:
        cmd = ["syft", f"registry:{bare}", "--output", "json"]
        if platform:
            cmd += ["--platform", platform]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=1800, env=env)
        if not result.stdout.strip():
            return None
        return json.loads(result.stdout)
    except (subprocess.TimeoutExpired, subprocess.SubprocessError, json.JSONDecodeError, OSError):
        return None


def _run_syft_json_dir(path: str) -> dict | None:
    """Run Syft on a local directory and return parsed native JSON output.

    Uses the ``dir:`` scheme — no registry auth env vars needed.
    Returns ``None`` on any failure.
    """
    if not shutil.which("syft"):
        return None
    try:
        result = subprocess.run(
            ["syft", f"dir:{path}", "--output", "json"],
            capture_output=True,
            text=True,
            timeout=1800,
        )
        if not result.stdout.strip():
            return None
        return json.loads(result.stdout)
    except (subprocess.TimeoutExpired, subprocess.SubprocessError, json.JSONDecodeError, OSError):
        return None


def _run_grype_sbom(sbom_input: str) -> dict | None:
    """Feed a CycloneDX JSON SBOM string into Grype and return parsed JSON.

    Grype 0.109+ reads SBOM from stdin when invoked with no positional source
    argument (``sbom:-`` is broken in this version — it treats ``-`` as a
    literal filename).  Piping directly without a source arg is the supported
    stdin path as documented: ``syft ... -o json | grype``.

    Returns ``None`` on any failure.
    """
    if not shutil.which("grype"):
        return None
    try:
        result = subprocess.run(
            [
                "grype",
                "--output", "json",
                "--add-cpes-if-none",
            ],
            input=sbom_input,
            capture_output=True,
            text=True,
            timeout=1800,
        )
        if not result.stdout.strip():
            return None
        return json.loads(result.stdout)
    except (subprocess.TimeoutExpired, subprocess.SubprocessError, json.JSONDecodeError, OSError):
        return None


def _syft_grype_scan(
    image_name: str,
    username: str | None = None,
    password: str | None = None,
) -> tuple[list[dict[str, Any]], str, str | None, list[str]] | None:
    """Run the Syft → Grype pipeline for a container image.

    Syft generates a CycloneDX SBOM by talking directly to the registry API
    (no full image pull).  Grype then scans the SBOM offline.

    Returns ``(findings, "syft+grype", base_image, chain)`` on success, or
    ``None`` if either tool is unavailable or produces no output.
    """
    sbom = _run_syft_sbom(image_name, username=username, password=password)
    if not sbom:
        return None
    grype_json = _run_grype_sbom(sbom)
    if grype_json is None:
        return None
    findings = _grype_results_to_findings(grype_json)
    base_image, base_image_chain = _extract_base_image_grype(grype_json)
    return findings, "syft+grype", base_image, base_image_chain


# ---------------------------------------------------------------------------
# Base image extraction helpers (container scans only)
# ---------------------------------------------------------------------------

def _extract_base_image_trivy(trivy_json: dict) -> tuple[str | None, list[str]]:
    """Extract base OS / base image info from Trivy JSON output.

    Strategy (in priority order):
    1. Check ``Metadata.ImageConfig.Labels`` for the OCI standard label
       ``org.opencontainers.image.base.name`` — set by buildkit on images
       built with ``--label``.
    2. Parse the ``os-pkgs`` Result target string, which Trivy formats as
       ``"<image> (<distro> <version>)"`` — e.g. ``"nginx:1.27-alpine (alpine 3.21.3)"``.
       The parenthesised part is the base OS distro + version.
    3. Walk ``Metadata.ImageConfig.history`` for ``FROM scratch`` markers.

    Returns ``(base_image, chain)`` where:
    - ``base_image`` is the distro string (e.g. ``"alpine 3.21.3"`` or
      ``"debian 13.3"``) or the OCI label value, never the scanned image itself.
    - ``chain`` is populated with the OCI label or distro when found.
    """
    metadata = trivy_json.get("Metadata", {})
    image_config = metadata.get("ImageConfig", {})
    labels = image_config.get("Labels") or {}

    # 1. OCI label — most reliable when present
    oci_base = labels.get("org.opencontainers.image.base.name")

    # 2. Parse os-pkgs result target: "imagename (distro version)"
    os_distro: str | None = None
    import re as _re
    for result in trivy_json.get("Results", []):
        if result.get("Class") == "os-pkgs":
            target = result.get("Target", "")
            m = _re.search(r"\(([^)]+)\)$", target)
            if m:
                os_distro = m.group(1)  # e.g. "alpine 3.21.3"
            break

    # 3. Walk history for FROM scratch
    history = image_config.get("history") or []
    is_scratch = False
    for entry in history:
        if entry.get("empty_layer"):
            continue
        created_by: str = entry.get("created_by", "")
        if "#(nop)" in created_by and "FROM scratch" in created_by:
            is_scratch = True
            break

    # Resolve base_image — prefer OCI label, then OS distro, then scratch
    if oci_base:
        base_image = oci_base
        chain = [oci_base]
    elif os_distro:
        base_image = os_distro
        chain = [os_distro]
    elif is_scratch:
        base_image = "scratch"
        chain = ["scratch"]
    else:
        base_image = None
        chain = []

    return base_image, chain


def _extract_base_image_grype(grype_json: dict) -> tuple[str | None, list[str]]:
    """Extract base OS / base image info from Grype JSON output.

    Strategy (in priority order):
    1. Check ``source.target.labels`` for the OCI standard label
       ``org.opencontainers.image.base.name``.
    2. Use the top-level ``distro`` object (``{"name": "alpine", "version": "3.21.3"}``),
       which Grype always populates for image scans.

    Returns ``(base_image, chain)``.
    """
    source = grype_json.get("source", {})
    target = source.get("target", {})
    # When Grype scans a dir: target, "target" is a plain string, not a dict
    if not isinstance(target, dict):
        target = {}
    labels = target.get("labels") or {}

    # 1. OCI label
    oci_base = labels.get("org.opencontainers.image.base.name")

    # 2. Top-level distro object
    distro = grype_json.get("distro") or {}
    distro_name = distro.get("name")
    distro_version = distro.get("version")
    os_distro: str | None = None
    if distro_name:
        os_distro = f"{distro_name} {distro_version}".strip() if distro_version else distro_name

    if oci_base:
        base_image = oci_base
        chain = [oci_base]
    elif os_distro:
        base_image = os_distro
        chain = [os_distro]
    else:
        base_image = None
        chain = []

    return base_image, chain


# ---------------------------------------------------------------------------
# osv-scanner integration helpers (Google OSV-Scanner CLI)
# https://github.com/google/osv-scanner
# ---------------------------------------------------------------------------

def _cvss_score_to_severity(score: float) -> str:
    """Map a numeric CVSS score to a severity label."""
    if score >= 9.0:
        return "CRITICAL"
    elif score >= 7.0:
        return "HIGH"
    elif score >= 4.0:
        return "MEDIUM"
    elif score > 0:
        return "LOW"
    return "UNKNOWN"


def _severity_from_osv(
    vuln: dict,
    group_max_severity: float | None = None,
) -> tuple[str, float | None]:
    """Extract severity and CVSS score from an osv-scanner vulnerability object.

    Lookup priority:
    1. ``severity[]`` entries where type is CVSS_V2/V3/V4 and the score
       field is a plain numeric value.
    2. ``database_specific.severity`` keyword (CRITICAL/HIGH/MODERATE/MEDIUM/LOW).
    3. ``group_max_severity`` numeric score from the parent package group
       (the only numeric source for many OS-package advisories like Debian).
    """
    severity = "UNKNOWN"
    cvss_score: float | None = None

    nvd_score: float | None = None
    for sev in vuln.get("severity") or []:
        sev_type = sev.get("type", "")
        score_val = sev.get("score", "")
        if sev_type in ("CVSS_V2", "CVSS_V3", "CVSS_V4"):
            if isinstance(score_val, (int, float)):
                nvd_score = float(score_val)
                break
            try:
                nvd_score = float(score_val)
                break
            except (ValueError, TypeError):
                pass

    if nvd_score is not None:
        cvss_score = nvd_score
        severity = _cvss_score_to_severity(cvss_score)

    if severity == "UNKNOWN":
        db_sev = (
            (vuln.get("database_specific") or {}).get("severity", "") or ""
        ).upper()
        if db_sev == "MODERATE":
            db_sev = "MEDIUM"
        if db_sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
            severity = db_sev
            cvss_score = {"CRITICAL": 9.5, "HIGH": 7.5, "MEDIUM": 5.0, "LOW": 2.0}[db_sev]

    if severity == "UNKNOWN" and group_max_severity is not None:
        cvss_score = group_max_severity
        severity = _cvss_score_to_severity(cvss_score)

    return severity, cvss_score


def _fix_version_from_osv(vuln: dict, ecosystem: str) -> str | None:
    for affected in vuln.get("affected", []):
        for rng in affected.get("ranges", []):
            for event in rng.get("events", []):
                if "fixed" in event:
                    return event["fixed"]
    return None


def _run_osv_scanner_json(
    image_name: str,
    username: str | None = None,
    password: str | None = None,
) -> dict | None:
    """Invoke osv-scanner against a container image and return parsed JSON.

    Runs ``osv-scanner scan image <image_name> --format json``.  osv-scanner
    handles multi-platform images natively so no ``--platform`` flag is needed.

    ``username`` / ``password`` are forwarded via the standard Docker credential
    environment variables when provided.

    Returns ``None`` if osv-scanner is not installed, the scan fails, or the
    output cannot be parsed as JSON.
    """
    if not shutil.which("osv-scanner"):
        return None
    import os
    env = os.environ.copy()
    # osv-scanner respects standard Docker config for registry auth.
    # We surface credentials via environment variables that Docker CLI honours.
    if username:
        env["DOCKER_USERNAME"] = username
    if password:
        env["DOCKER_PASSWORD"] = password
    cmd = [
        "osv-scanner",
        "scan",
        "image",
        image_name,
        "--format", "json",
    ]
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=1800,
            env=env,
        )
        stdout = result.stdout.strip()
        if not stdout:
            return None
        return json.loads(stdout)
    except (subprocess.TimeoutExpired, subprocess.SubprocessError, json.JSONDecodeError, OSError):
        return None


def _osv_scanner_results_to_findings(osv_json: dict) -> list[dict[str, Any]]:
    """Convert osv-scanner JSON output to the internal finding dict format.

    osv-scanner JSON structure (v2.x):
    {
      "results": [
        {
          "packages": [
            {
              "package": {"name": ..., "version": ..., "ecosystem": ...},
              "vulnerabilities": [
                {
                  "id": ...,
                  "aliases": [...],
                  "summary": ...,
                  "severity": [{"type": "CVSS_V3", "score": "..."}],
                  "affected": [...],
                  "references": [{"url": ...}],
                  "database_specific": {"severity": "HIGH"},
                }
              ]
            }
          ]
        }
      ]
    }
    """
    findings: list[dict[str, Any]] = []

    for result_block in osv_json.get("results", []):
        for pkg_entry in result_block.get("packages", []):
            pkg = pkg_entry.get("package", {})
            pkg_name = pkg.get("name", "unknown")
            pkg_version = pkg.get("version", "unknown")
            pkg_ecosystem = pkg.get("ecosystem", "unknown")

            # Build a vuln-id → numeric max_severity map from the groups list.
            # groups[].max_severity is the only numeric CVSS score available for
            # many OS-package advisories (e.g. Debian) where the vulnerability
            # object itself carries no database_specific.severity keyword.
            group_score_by_id: dict[str, float] = {}
            for grp in pkg_entry.get("groups") or []:
                raw = grp.get("max_severity", "")
                try:
                    score = float(raw)
                except (ValueError, TypeError):
                    score = 0.0
                for vid in grp.get("ids") or []:
                    group_score_by_id[vid] = score

            for vuln in pkg_entry.get("vulnerabilities", []):
                vuln_id = vuln.get("id", "UNKNOWN")
                group_max = group_score_by_id.get(vuln_id)
                severity, cvss_score = _severity_from_osv(vuln, group_max_severity=group_max)

                fix_version = _fix_version_from_osv(vuln, pkg_ecosystem)
                is_fixed = fix_version is not None

                aliases = [a for a in vuln.get("aliases", []) if a != vuln.get("id")]
                refs = [r.get("url", "") for r in vuln.get("references", []) if r.get("url")]

                findings.append(
                    {
                        "id": str(uuid4()),
                        "package_name": pkg_name,
                        "package_version": pkg_version,
                        "package_ecosystem": pkg_ecosystem,
                        "vulnerability_id": vuln_id,
                        "severity": severity,
                        "cvss_score": cvss_score,
                        "description": vuln.get("summary", vuln.get("details", ""))[:500],
                        "fix_version": fix_version,
                        "is_fixed": is_fixed,
                        "reachable": False,
                        "exploitable": False,
                        "risk_score": compute_risk_score(cvss_score, severity, False, False),
                        "aliases": aliases,
                        "references": refs,
                    }
                )

    return findings


# ---------------------------------------------------------------------------
# Windows layer-extraction helpers
# ---------------------------------------------------------------------------

def _resolve_registry_auth(
    image_name: str,
    username: str | None = None,
    password: str | None = None,
) -> tuple[str, str, str, str | None]:
    """Parse an image reference and resolve a Bearer token for registry API calls.

    Returns ``(host, repo, tag, token)``.  ``token`` is ``None`` when the
    registry requires no auth or the token exchange fails.
    """
    ref = image_name
    tag = "latest"
    if "@" in ref.split("/")[-1]:
        ref, tag = ref.rsplit("@", 1)
    elif ":" in ref.split("/")[-1]:
        ref, tag = ref.rsplit(":", 1)

    parts = ref.split("/")
    if len(parts) == 1 or ("." not in parts[0] and ":" not in parts[0] and parts[0] != "localhost"):
        host = "registry-1.docker.io"
        repo = f"library/{ref}" if len(parts) == 1 else ref
    else:
        host = parts[0]
        repo = "/".join(parts[1:])

    token: str | None = None
    try:
        auth_challenge: dict[str, str] = {}
        with httpx.Client(timeout=8) as client:
            r = client.get(f"https://{host}/v2/", headers={"Accept": "application/json"})
            if r.status_code == 401:
                www = r.headers.get("www-authenticate", "")
                if www.lower().startswith("bearer "):
                    for m in re.finditer(r'(\w+)="([^"]*)"', www[7:]):
                        auth_challenge[m.group(1)] = m.group(2)
        realm = auth_challenge.get("realm")
        if realm:
            params: dict[str, str] = {
                "service": auth_challenge.get("service", host),
                "scope": f"repository:{repo}:pull",
            }
            auth = (username, password) if username and password else None
            with httpx.Client(timeout=8) as client:
                tr = client.get(realm, params=params, auth=auth)
                if tr.status_code == 200:
                    token = tr.json().get("token") or tr.json().get("access_token")
    except Exception:
        pass

    return host, repo, tag, token


def _fetch_windows_manifest(
    host: str,
    repo: str,
    tag: str,
    token: str | None,
) -> dict | None:
    """Fetch the windows/amd64 single-platform manifest for a given image.

    If the tag resolves to a manifest list (index), automatically selects
    the ``windows/amd64`` child manifest and fetches it.  Returns the
    single-platform manifest dict (with a ``layers`` key) or ``None`` on
    any failure.
    """
    headers: dict[str, str] = {
        "Accept": (
            "application/vnd.oci.image.index.v1+json,"
            "application/vnd.docker.distribution.manifest.list.v2+json,"
            "application/vnd.docker.distribution.manifest.v2+json,"
            "application/vnd.oci.image.manifest.v1+json"
        )
    }
    if token:
        headers["Authorization"] = f"Bearer {token}"

    try:
        with httpx.Client(timeout=30) as client:
            r = client.get(f"https://{host}/v2/{repo}/manifests/{tag}", headers=headers)
        if r.status_code != 200:
            return None
        manifest = r.json()
    except Exception:
        return None

    media_type = manifest.get("mediaType", "")
    if "index" in media_type or "manifest.list" in media_type or "manifests" in manifest:
        # Multi-platform index — find the windows/amd64 child
        win_entry = next(
            (
                m for m in manifest.get("manifests", [])
                if m.get("platform", {}).get("os", "").lower() == "windows"
                and m.get("platform", {}).get("architecture", "amd64").lower() == "amd64"
            ),
            None,
        )
        if not win_entry:
            return None
        digest = win_entry.get("digest")
        if not digest:
            return None
        try:
            with httpx.Client(timeout=30) as client:
                r = client.get(
                    f"https://{host}/v2/{repo}/manifests/{digest}",
                    headers={
                        "Accept": (
                            "application/vnd.oci.image.manifest.v1+json,"
                            "application/vnd.docker.distribution.manifest.v2+json"
                        ),
                        **({"Authorization": f"Bearer {token}"} if token else {}),
                    },
                )
            if r.status_code != 200:
                return None
            return r.json()
        except Exception:
            return None

    return manifest


def _download_layer_blob(
    host: str,
    repo: str,
    digest: str,
    token: str | None,
    dest_dir: "Path",
) -> "Path | None":
    """Stream a registry layer blob to a file in ``dest_dir``.

    Returns the ``Path`` to the downloaded file, or ``None`` on failure.
    Deleting the file after extraction is the caller's responsibility.
    """
    from pathlib import Path as _Path
    headers: dict[str, str] = {}
    if token:
        headers["Authorization"] = f"Bearer {token}"

    filename = dest_dir / f"layer-{digest.replace(':', '-')}.tar.gz"
    try:
        # follow_redirects=True is required: MCR and many registries redirect
        # blob requests to CDN storage (Azure Blob, S3, etc.) via HTTP 307.
        with httpx.Client(timeout=httpx.Timeout(None, connect=30), follow_redirects=True) as client:
            with client.stream("GET", f"https://{host}/v2/{repo}/blobs/{digest}", headers=headers) as r:
                if r.status_code != 200:
                    return None
                with open(filename, "wb") as f:
                    for chunk in r.iter_bytes(chunk_size=1024 * 1024):
                        f.write(chunk)
        return filename
    except Exception:
        try:
            filename.unlink(missing_ok=True)
        except Exception:
            pass
        return None


def _extract_layer_tar(blob_path: "Path", dest_dir: "Path") -> None:
    """Extract an OCI layer tar archive into ``dest_dir``.

    Handles Docker whiteout files (``.wh.`` prefix for file deletion,
    ``.wh..wh..opq`` for opaque directory replacement) and rejects unsafe
    tar members (absolute paths, path traversal).
    """
    import tarfile as _tarfile
    import shutil as _shutil
    from pathlib import Path as _Path

    try:
        with _tarfile.open(blob_path, "r:*") as tar:
            for member in tar.getmembers():
                # Reject absolute paths and path traversal
                norm = member.name.replace("\\", "/")
                parts = norm.split("/")
                if any(p == ".." for p in parts) or norm.startswith("/"):
                    continue

                basename = _Path(norm).name
                parent = _Path(norm).parent

                if basename == ".wh..wh..opq":
                    # Opaque whiteout: clear the parent directory
                    target = dest_dir / parent
                    if target.is_dir():
                        _shutil.rmtree(target)
                        target.mkdir(parents=True, exist_ok=True)
                    continue

                if basename.startswith(".wh."):
                    # Regular whiteout: delete the referenced path
                    real = dest_dir / parent / basename[4:]
                    if real.is_dir():
                        _shutil.rmtree(real)
                    elif real.exists():
                        real.unlink(missing_ok=True)
                    continue

                try:
                    tar.extract(member, path=dest_dir, set_attrs=False)
                except Exception:
                    pass  # skip device files and other unextractable entries
    except Exception as exc:
        import logging as _logging
        _logging.getLogger(__name__).warning("Layer extraction warning for %s: %s", blob_path, exc)


# ---------------------------------------------------------------------------
# Public scan functions
# ---------------------------------------------------------------------------

def scan_container_windows_pe_version(
    image_name: str,
    username: str | None = None,
    password: str | None = None,
    scanner: str = "grype",
) -> tuple[list[dict[str, Any]], str, str | None, list[str]]:
    """Scan a Windows container image using PE DLL version matching (default mode).

    ``scanner`` selects the CVE-matching engine: ``"grype"`` (default) feeds a
    Syft SBOM into Grype; ``"trivy"`` runs ``trivy image --platform windows/amd64``
    directly against the registry.

    In both cases MSRC CVRF matching is applied on top for OS-level KB CVEs.
    """
    from .msrc import scan_windows_os_cves

    if scanner == "trivy":
        trivy_json = _run_trivy_json(
            image_name,
            scan_type="image",
            username=username,
            password=password,
            platform="windows/amd64",
        )
        if not trivy_json:
            raise WindowsImageUnsupportedError(
                f"Windows container image scan failed: Trivy returned no output for "
                f"{image_name}. Ensure Trivy is installed and the registry is reachable."
            )
        findings = _trivy_results_to_findings(trivy_json)
        base_image, base_image_chain = _extract_base_image_trivy(trivy_json)
        # MSRC OS CVEs — derive build from Trivy artifacts via PE metadata
        syft_json = _run_syft_json(image_name, username=username, password=password, platform="windows/amd64")
        artifacts = syft_json.get("artifacts", []) if syft_json else []
        msrc_findings = scan_windows_os_cves(artifacts)
        return findings + msrc_findings, "trivy (windows)", base_image, base_image_chain

    # Default: Syft → Grype
    syft_json = _run_syft_json(image_name, username=username, password=password, platform="windows/amd64")
    if not syft_json:
        raise WindowsImageUnsupportedError(
            f"Windows container image scan failed: Syft could not enumerate packages "
            f"for {image_name}. Ensure Syft is installed and the registry is reachable."
        )

    syft_json_str = json.dumps(syft_json)
    grype_json = _run_grype_sbom(syft_json_str)
    if grype_json is None:
        raise WindowsImageUnsupportedError(
            f"Windows container image scan failed: Grype returned no output for "
            f"{image_name}. Ensure Grype is installed."
        )

    grype_findings = _grype_results_to_findings(grype_json)
    base_image, base_image_chain = _extract_base_image_grype(grype_json)
    artifacts = syft_json.get("artifacts", [])
    msrc_findings = scan_windows_os_cves(artifacts)
    return grype_findings + msrc_findings, "syft+grype (windows)", base_image, base_image_chain


def scan_container_windows_layer_extract(
    image_name: str,
    username: str | None = None,
    password: str | None = None,
    scanner: str = "grype",
) -> tuple[list[dict[str, Any]], str, str | None, list[str]]:
    """Scan a Windows container image via full layer extraction.

    Downloads every image layer from the registry, merges them into a
    temporary directory, then:
      1. Parses the Windows SOFTWARE registry hive for the exact OS build
         and cumulative update revision (ground truth vs PE DLL inference).
      2. Runs Syft (``dir:`` scheme) on the extracted filesystem for package
         enumeration.
      3. Feeds the Syft SBOM into Grype for language/binary CVE matching.
      4. Runs MSRC CVRF matching using the registry-derived build number.

    Falls back to PE-version MSRC matching if the registry hive is absent
    or unreadable (e.g. nanoserver images that omit System32/config/).

    Raises ``WindowsImageUnsupportedError`` if manifest fetch, layer
    download, or Grype fails outright.
    """
    import tempfile
    from pathlib import Path as _Path
    from .msrc import extract_windows_build_from_registry, _scan_msrc_for_build, scan_windows_os_cves

    host, repo, tag, token = _resolve_registry_auth(image_name, username, password)

    manifest = _fetch_windows_manifest(host, repo, tag, token)
    if not manifest:
        raise WindowsImageUnsupportedError(
            f"Could not fetch windows/amd64 manifest for {image_name}"
        )

    layers = manifest.get("layers", [])
    if not layers:
        raise WindowsImageUnsupportedError(
            f"Manifest for {image_name} has no layers"
        )

    with tempfile.TemporaryDirectory(prefix="dunedain-win-") as tmpdir:
        tmp_path = _Path(tmpdir)

        for layer in layers:
            # Guard: some manifest formats embed non-dict entries (foreign layer refs)
            if not isinstance(layer, dict):
                continue
            digest = layer.get("digest", "")
            if not digest:
                continue
            blob_path = _download_layer_blob(host, repo, digest, token, tmp_path)
            if blob_path:
                _extract_layer_tar(blob_path, tmp_path)
                blob_path.unlink(missing_ok=True)

        # Ground-truth OS build from the SOFTWARE registry hive
        build_result = extract_windows_build_from_registry(tmp_path)

        if scanner == "trivy":
            # Trivy fs scan on the extracted directory
            trivy_json = _run_trivy_json(tmpdir, scan_type="fs")
            if not isinstance(trivy_json, dict):
                raise WindowsImageUnsupportedError(
                    f"Trivy found no output for extracted layers of {image_name}"
                )
            scan_findings = _trivy_results_to_findings(trivy_json)
            base_image, base_image_chain = _extract_base_image_trivy(trivy_json)
            engine_label = "trivy (windows/layer-extract)"
            artifacts_for_msrc: list = []
        else:
            # Syft dir: scan for package enumeration + SBOM
            syft_json = _run_syft_json_dir(tmpdir)
            if not isinstance(syft_json, dict):
                syft_json = None
            syft_str = json.dumps(syft_json) if syft_json else None

            if syft_str:
                grype_json = _run_grype_sbom(syft_str)
            else:
                grype_json = _run_grype_json(f"dir:{tmpdir}")

            if not isinstance(grype_json, dict):
                raise WindowsImageUnsupportedError(
                    f"Grype found no output for extracted layers of {image_name}"
                )
            scan_findings = _grype_results_to_findings(grype_json)
            base_image, base_image_chain = _extract_base_image_grype(grype_json)
            engine_label = "syft+grype (windows/layer-extract)"
            artifacts_for_msrc = syft_json.get("artifacts", []) if isinstance(syft_json, dict) else []

        # MSRC OS CVE matching — prefer registry hive build, fall back to PE artifacts
        if build_result:
            baseline, revision = build_result
            msrc_findings = _scan_msrc_for_build(baseline, revision)
        else:
            msrc_findings = scan_windows_os_cves(artifacts_for_msrc)

    return (
        scan_findings + msrc_findings,
        engine_label,
        base_image,
        base_image_chain,
    )


def scan_container_windows(
    image_name: str,
    username: str | None = None,
    password: str | None = None,
    scanner_override: str | None = None,
) -> tuple[list[dict[str, Any]], str, str | None, list[str]]:
    """Dispatch Windows container scanning based on settings or scanner_override.

    ``scanner_override`` format: ``"win:<mode>:<scanner>"`` e.g. ``"win:layer_extraction:trivy"``.
    When absent, reads ``windows_scanner_mode`` and ``windows_scanner_backend`` from the DB.
    """
    if scanner_override and scanner_override.lower().startswith("win:"):
        parts = scanner_override.lower().split(":")
        # parts: ["win", "<mode>", "<scanner>"] — scanner may be absent (legacy)
        mode = parts[1] if len(parts) > 1 else _get_windows_scanner_mode()
        scanner = parts[2] if len(parts) > 2 else _get_windows_scanner_backend()
    else:
        mode = _get_windows_scanner_mode()
        scanner = _get_windows_scanner_backend()

    if mode == "layer_extraction":
        return scan_container_windows_layer_extract(image_name, username=username, password=password, scanner=scanner)
    return scan_container_windows_pe_version(image_name, username=username, password=password, scanner=scanner)


def scan_container(
    image_name: str,
    username: str | None = None,
    password: str | None = None,
    scanner_override: str | None = None,
) -> tuple[list[dict[str, Any]], str, str | None, list[str]]:
    """Scan a container image for vulnerabilities.

    Returns ``(findings, engine_used, base_image, base_image_chain)``.

    Scanning strategy is controlled by the ``scanner_backend`` app setting,
    or by ``scanner_override`` when set (used for comparison scans):

    * ``auto``        — Try Trivy first, then Grype. Raises if both fail.
    * ``trivy``       — Trivy scan. Raises if Trivy fails.
    * ``grype``       — Grype scan. Raises if Grype fails.
    * ``syft_grype``  — Syft (registry-native SBOM) + Grype. Raises if either fails.
    * ``osv_scanner`` — osv-scanner container scan. Raises if it fails.

    Raises ``RuntimeError`` if the selected scanner is unavailable or returns
    no output — the caller is responsible for marking the scan as failed.
    No silent fallback to OSV-only ever occurs.
    """
    raw_override = scanner_override.lower() if scanner_override else None
    # "win:<mode>" overrides are Windows-only intent — treat as no Linux preference.
    if raw_override and raw_override.startswith("win:"):
        raw_override = None
    pref = raw_override or _get_scanner_preference()
    use_trivy = pref in ("auto", "trivy")
    use_grype = pref in ("auto", "grype")
    use_syft_grype = pref == "syft_grype"
    use_osv_scanner = pref == "osv_scanner"

    # Detect Windows-only images and route to the Windows scanner path.
    # Grype can scan Windows images from a Linux host — it finds language
    # packages (.NET, Node, Java, Python, etc.) and binary-matched CVEs (7-Zip,
    # SQLite, OpenSSL, etc. via PE version resources).  OS-level KB patch CVEs
    # are not covered without a custom MSRC-backed database.
    target_path = Path(image_name)
    is_dockerfile = target_path.is_file() and (
        target_path.name.lower().startswith("dockerfile")
        or target_path.name.lower().endswith(".dockerfile")
    )
    if not is_dockerfile:
        detected_platform = _detect_image_platform(image_name)
        if detected_platform == "windows/amd64":
            return scan_container_windows(
                image_name,
                username=username,
                password=password,
                scanner_override=scanner_override,
            )

    # 0. Syft → Grype pipeline (registry-native, no full image pull)
    if use_syft_grype:
        result = _syft_grype_scan(image_name, username=username, password=password)
        if result is None:
            raise RuntimeError(f"syft+grype scan failed for image: {image_name}")
        return result

    # 0b. osv-scanner container scan
    if use_osv_scanner:
        if username or password:
            raise RuntimeError(
                "osv-scanner does not support authenticated registries. "
                "Switch the comparison engine to Trivy or Grype for private images."
            )
        osv_json = _run_osv_scanner_json(image_name, username=username, password=password)
        if osv_json is None:
            raise RuntimeError(f"osv-scanner scan failed for image: {image_name}")
        findings = _osv_scanner_results_to_findings(osv_json)
        return findings, "osv_scanner", None, []

    # 1. Trivy image scan
    if use_trivy:
        trivy_json = _run_trivy_json(image_name, scan_type="image", username=username, password=password)
        if trivy_json is not None:
            trivy_findings = _trivy_results_to_findings(trivy_json)
            base_image, base_image_chain = _extract_base_image_trivy(trivy_json)
            return trivy_findings, "trivy", base_image, base_image_chain
        elif pref == "trivy":
            raise RuntimeError(f"trivy scan failed for image: {image_name}")
        # auto: fall through to grype

    # 2. Grype image scan
    if use_grype:
        grype_json = _run_grype_json(image_name, username=username, password=password)
        if grype_json is not None:
            grype_findings = _grype_results_to_findings(grype_json)
            base_image, base_image_chain = _extract_base_image_grype(grype_json)
            return grype_findings, "grype", base_image, base_image_chain
        elif pref == "grype":
            raise RuntimeError(f"grype scan failed for image: {image_name}")
        # auto: fall through to Dockerfile path or raise below

    # 3a. Dockerfile — try preferred scanner on the parent directory first
    target_path = Path(image_name)
    filename = target_path.name.lower()
    is_dockerfile = target_path.is_file() and (
        filename.startswith("dockerfile") or filename.endswith(".dockerfile")
    )
    if is_dockerfile:
        if use_trivy:
            trivy_json = _run_trivy_json(str(target_path.parent), scan_type="fs")
            if trivy_json is not None:
                return _trivy_results_to_findings(trivy_json), "trivy", None, []

        if use_grype:
            grype_json = _run_grype_json(f"dir:{target_path.parent}")
            if grype_json is not None:
                return _grype_results_to_findings(grype_json), "grype", None, []

    raise RuntimeError(f"No scanner succeeded for image: {image_name} (backend: {pref})")



def _run_osv_scanner_source_json(sbom_path: str) -> dict | None:
    """Invoke osv-scanner against a CycloneDX SBOM file and return parsed JSON.

    Runs ``osv-scanner scan source -L <sbom_path> --format json``.  The SBOM
    file must be named ``bom.json`` as required by the osv-scanner lockfile
    heuristic.

    Returns ``None`` if osv-scanner is not installed, the scan fails, or the
    output cannot be parsed as JSON.
    """
    if not shutil.which("osv-scanner"):
        return None
    cmd = [
        "osv-scanner",
        "scan",
        "source",
        "-L", sbom_path,
        "--format", "json",
    ]
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=1800,
        )
        stdout = result.stdout.strip()
        if not stdout:
            return None
        return json.loads(stdout)
    except (subprocess.TimeoutExpired, subprocess.SubprocessError, json.JSONDecodeError, OSError):
        return None


def scan_source(source_path: str) -> tuple[list[dict[str, Any]], str]:
    """Scan a source directory for vulnerabilities.

    Returns ``(findings, engine_used)`` where ``engine_used`` is one of
    ``"trivy"``, ``"grype"``, ``"syft+grype"``, or ``"osv_scanner"``.

    Scanning strategy is controlled by the ``scanner_backend`` app setting:

    * ``auto``        — Try Trivy first, then Grype. Raises if both fail.
    * ``trivy``       — Trivy fs scan. Raises if Trivy fails.
    * ``grype``       — Grype dir scan. Raises if Grype fails.
    * ``syft_grype``  — Syft SBOM + Grype. Raises if either fails.
    * ``osv_scanner`` — Syft SBOM → osv-scanner scan source. Raises if either fails.

    No silent fallback ever occurs for explicit backends.
    """
    import tempfile
    import os

    path = Path(source_path)
    pref = _get_scanner_preference()

    # ── osv_scanner: Syft SBOM → osv-scanner scan source ─────────────────
    if pref == "osv_scanner":
        sbom = _run_syft_sbom(source_path)
        if sbom is None:
            raise RuntimeError(f"syft failed to generate SBOM for source: {source_path}")
        with tempfile.TemporaryDirectory() as tmpdir:
            bom_path = os.path.join(tmpdir, "bom.json")
            Path(bom_path).write_text(sbom)
            osv_json = _run_osv_scanner_source_json(bom_path)
        if osv_json is None:
            raise RuntimeError(f"osv-scanner source scan failed for: {source_path}")
        return _osv_scanner_results_to_findings(osv_json), "osv_scanner"

    # ── syft_grype: Syft SBOM → Grype ────────────────────────────────────
    if pref == "syft_grype":
        sbom = _run_syft_sbom(source_path)
        if sbom is None:
            raise RuntimeError(f"syft failed to generate SBOM for source: {source_path}")
        grype_json = _run_grype_sbom(sbom)
        if grype_json is None:
            raise RuntimeError(f"grype failed to scan SBOM for source: {source_path}")
        grype_findings = _grype_results_to_findings(grype_json)
        return grype_findings, "syft+grype"

    use_trivy = pref in ("auto", "trivy")
    use_grype = pref in ("auto", "grype")

    # 1. Trivy filesystem scan
    if path.is_dir() and use_trivy:
        trivy_json = _run_trivy_json(str(path), scan_type="fs")
        if trivy_json is not None:
            return _trivy_results_to_findings(trivy_json), "trivy"
        elif pref == "trivy":
            raise RuntimeError(f"trivy scan failed for source: {source_path}")
        # auto: fall through to grype

    # 2. Grype directory scan
    if path.is_dir() and use_grype:
        grype_json = _run_grype_json(f"dir:{path}")
        if grype_json is not None:
            return _grype_results_to_findings(grype_json), "grype"
        elif pref == "grype":
            raise RuntimeError(f"grype scan failed for source: {source_path}")

    raise RuntimeError(f"No scanner succeeded for source: {source_path} (backend: {pref})")
