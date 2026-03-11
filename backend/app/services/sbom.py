from __future__ import annotations

from datetime import datetime, timezone
from typing import Any
from uuid import uuid4


def generate_sbom(scan: Any, findings: list[Any]) -> dict[str, Any]:
    """Generate a CycloneDX 1.4 JSON SBOM from a scan and its findings."""
    seen: dict[str, dict] = {}
    for f in findings:
        key = f"{f.package_ecosystem}/{f.package_name}@{f.package_version}"
        if key not in seen:
            seen[key] = {
                "type": "library",
                "bom-ref": str(uuid4()),
                "name": f.package_name,
                "version": f.package_version,
                "purl": _purl(f.package_ecosystem, f.package_name, f.package_version),
                "ecosystem": f.package_ecosystem,
            }

    vulnerabilities = []
    for f in findings:
        comp_key = f"{f.package_ecosystem}/{f.package_name}@{f.package_version}"
        comp = seen.get(comp_key, {})
        vuln: dict[str, Any] = {
            "bom-ref": str(uuid4()),
            "id": f.vulnerability_id,
            "description": f.description or "",
            "ratings": [],
            "affects": [{"ref": comp.get("bom-ref", "")}],
        }
        if f.cvss_score is not None:
            vuln["ratings"].append(
                {
                    "source": {"name": "OSV"},
                    "score": f.cvss_score,
                    "severity": f.severity.lower(),
                    "method": "CVSSv3",
                }
            )
        if f.aliases:
            vuln["aliases"] = [{"id": a} for a in f.aliases]
        if f.references:
            vuln["references"] = [{"id": r, "source": {"url": r}} for r in f.references]
        vulnerabilities.append(vuln)

    sbom: dict[str, Any] = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.4",
        "serialNumber": f"urn:uuid:{uuid4()}",
        "version": 1,
        "metadata": {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "tools": [{"vendor": "Dunedain", "name": "Dunedain Security Platform", "version": "1.0.0"}],
            "component": {
                "type": "application",
                "name": scan.name,
                "description": f"Scan target: {scan.target}",
            },
        },
        "components": list(seen.values()),
        "vulnerabilities": vulnerabilities,
    }
    return sbom


def parse_sbom(content: dict[str, Any]) -> list[dict[str, Any]]:
    """Parse packages from a CycloneDX or SPDX SBOM and return package dicts."""
    bom_format = content.get("bomFormat", "").lower()

    if bom_format == "cyclonedx" or "components" in content:
        return _parse_cyclonedx(content)

    # SPDX JSON
    if "spdxVersion" in content or "packages" in content:
        return _parse_spdx(content)

    return []


def _purl(ecosystem: str, name: str, version: str) -> str:
    eco_map = {
        "pypi": "pypi",
        "npm": "npm",
        "maven": "maven",
        "go": "golang",
        "crates.io": "cargo",
        "rubygems": "gem",
        "nuget": "nuget",
    }
    pkg_type = eco_map.get(ecosystem.lower(), ecosystem.lower())
    return f"pkg:{pkg_type}/{name}@{version}"


def _parse_cyclonedx(content: dict[str, Any]) -> list[dict[str, Any]]:
    packages = []
    for comp in content.get("components", []):
        name = comp.get("name", "")
        version = comp.get("version", "")
        purl = comp.get("purl", "")
        ecosystem = _ecosystem_from_purl(purl) or "unknown"
        if name and version:
            packages.append({"name": name, "version": version, "ecosystem": ecosystem})
    return packages


def _parse_spdx(content: dict[str, Any]) -> list[dict[str, Any]]:
    packages = []
    for pkg in content.get("packages", []):
        name = pkg.get("name", "")
        version = pkg.get("versionInfo", "")
        # Try to derive ecosystem from ExternalRef PURL
        ecosystem = "unknown"
        for ref in pkg.get("externalRefs", []):
            if ref.get("referenceType") == "purl":
                ecosystem = _ecosystem_from_purl(ref.get("referenceLocator", "")) or "unknown"
                break
        if name and version:
            packages.append({"name": name, "version": version, "ecosystem": ecosystem})
    return packages


def _ecosystem_from_purl(purl: str) -> str | None:
    # purl format: pkg:<type>/<namespace>/<name>@<version>
    if not purl.startswith("pkg:"):
        return None
    pkg_type = purl[4:].split("/")[0].split("@")[0].lower()
    purl_to_osv = {
        "pypi": "PyPI",
        "npm": "npm",
        "maven": "Maven",
        "golang": "Go",
        "cargo": "crates.io",
        "gem": "RubyGems",
        "nuget": "NuGet",
    }
    return purl_to_osv.get(pkg_type, pkg_type)
