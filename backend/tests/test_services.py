"""Tests for scanner services."""
import pytest
from unittest.mock import MagicMock, patch
from app.services.risk import compute_risk_score, prioritize_findings
from app.services.scanner import (
    _trivy_results_to_findings,
    _grype_results_to_findings,
    scan_container,
    WindowsImageUnsupportedError,
)
from app.services.msrc import (
    extract_windows_build,
    _extract_cves_from_feed,
    scan_windows_os_cves,
)


def test_compute_risk_score_critical():
    # CRITICAL with high CVSS and both exploit flags multiplied: min(9.8 * 1.5 * 1.3, 10.0) = 10.0
    score = compute_risk_score(9.8, "CRITICAL", True, True)
    assert score > 9.0


def test_compute_risk_score_low():
    # LOW with low CVSS, no exploit flags: 1.0 * 1 * 1 = 1.0
    score = compute_risk_score(1.0, "LOW", False, False)
    assert score < 5.0


def test_prioritize_findings():
    findings = []
    for severity, cvss in [("LOW", 2.0), ("CRITICAL", 9.8), ("HIGH", 7.5)]:
        f = MagicMock()
        f.severity = severity
        f.cvss_score = cvss
        f.exploitable = False
        f.reachable = False
        f.risk_score = cvss
        findings.append(f)

    prioritized = prioritize_findings(findings)
    assert prioritized[0].risk_score >= prioritized[-1].risk_score


# ---------------------------------------------------------------------------
# Trivy JSON parsing tests
# ---------------------------------------------------------------------------

SAMPLE_TRIVY_JSON = {
    "Results": [
        {
            "Target": "python-app",
            "Class": "lang-pkgs",
            "Type": "python-pkg",
            "Vulnerabilities": [
                {
                    "VulnerabilityID": "CVE-2023-1234",
                    "PkgName": "requests",
                    "InstalledVersion": "2.25.0",
                    "FixedVersion": "2.28.0",
                    "Severity": "HIGH",
                    "Title": "SSRF vulnerability in requests",
                    "CVSS": {"nvd": {"V3Score": 7.5}},
                    "References": ["https://example.com/cve-2023-1234"],
                }
            ],
        },
        {
            "Target": "debian (debian 11.6)",
            "Class": "os-pkgs",
            "Type": "debian",
            "Vulnerabilities": [
                {
                    "VulnerabilityID": "CVE-2023-9999",
                    "PkgName": "libc6",
                    "InstalledVersion": "2.31-13",
                    "FixedVersion": "2.31-14",
                    "Severity": "MEDIUM",
                    "Title": "glibc buffer overflow",
                    "CVSS": {"nvd": {"V3Score": 5.5}},
                    "References": [],
                }
            ],
        },
    ]
}


def test_trivy_results_to_findings_count():
    """All Trivy vulnerabilities (OS + lang) become findings."""
    findings = _trivy_results_to_findings(SAMPLE_TRIVY_JSON)
    assert len(findings) == 2


def test_trivy_results_to_findings_severity():
    findings = _trivy_results_to_findings(SAMPLE_TRIVY_JSON)
    sevs = {f["vulnerability_id"]: f["severity"] for f in findings}
    assert sevs["CVE-2023-1234"] == "HIGH"
    assert sevs["CVE-2023-9999"] == "MEDIUM"


def test_trivy_results_to_findings_fix_version():
    findings = _trivy_results_to_findings(SAMPLE_TRIVY_JSON)
    req_finding = next(f for f in findings if f["vulnerability_id"] == "CVE-2023-1234")
    assert req_finding["fix_version"] == "2.28.0"
    assert req_finding["is_fixed"] is True


def test_trivy_results_to_findings_cvss():
    findings = _trivy_results_to_findings(SAMPLE_TRIVY_JSON)
    req_finding = next(f for f in findings if f["vulnerability_id"] == "CVE-2023-1234")
    assert req_finding["cvss_score"] == 7.5


def test_trivy_results_to_findings_ecosystem_mapping():
    """python-pkg type should be mapped to PyPI ecosystem."""
    findings = _trivy_results_to_findings(SAMPLE_TRIVY_JSON)
    req_finding = next(f for f in findings if f["package_name"] == "requests")
    assert req_finding["package_ecosystem"] == "PyPI"


# ---------------------------------------------------------------------------
# scan_container fallback tests
# ---------------------------------------------------------------------------

def test_scan_container_raises_when_no_scanner_and_not_dockerfile():
    """scan_container raises RuntimeError when neither Trivy nor Grype is available
    and the target is not a Dockerfile (no-silent-fallback contract)."""
    with patch("app.services.scanner._run_trivy_json", return_value=None), \
         patch("app.services.scanner._run_grype_json", return_value=None), \
         patch("app.services.scanner._detect_image_platform", return_value="linux/amd64"):
        with pytest.raises(RuntimeError):
            scan_container("nonexistent-image:latest")


def test_scan_container_windows_uses_syft_grype_and_returns_findings():
    """scan_container routes Windows images through Syft JSON → Grype pipeline
    (--platform windows/amd64) and returns findings with engine='syft+grype (windows)'."""
    fake_syft_json = {"artifacts": [], "distro": {}}
    grype_output = {
        "matches": [
            {
                "vulnerability": {
                    "id": "GHSA-gmc6-fwg3-75m5",
                    "severity": "High",
                    "cvss": [{"metrics": {"baseScore": 7.5}}],
                    "fix": {"state": "fixed", "versions": ["4.7.1"]},
                    "description": "MimeKit vulnerability",
                    "urls": [],
                },
                "artifact": {
                    "name": "MimeKit",
                    "version": "4.3.0.0",
                    "type": "dotnet",
                },
            }
        ],
        "distro": {"name": "", "version": "", "idLike": None},
    }
    with patch("app.services.scanner._detect_image_platform", return_value="windows/amd64"), \
         patch("app.services.scanner._run_syft_json", return_value=fake_syft_json) as mock_syft, \
         patch("app.services.scanner._run_grype_sbom", return_value=grype_output), \
         patch("app.services.msrc.scan_windows_os_cves", return_value=[]):
        findings, engine, base_image, chain = scan_container(
            "mcr.microsoft.com/windows/servercore:ltsc2022"
        )
    # Syft must be called with platform="windows/amd64"
    mock_syft.assert_called_once_with(
        "mcr.microsoft.com/windows/servercore:ltsc2022",
        username=None,
        password=None,
        platform="windows/amd64",
    )
    assert engine == "syft+grype (windows)"
    assert len(findings) == 1
    assert findings[0]["vulnerability_id"] == "GHSA-gmc6-fwg3-75m5"
    assert findings[0]["package_name"] == "MimeKit"
    assert findings[0]["severity"] == "HIGH"


def test_scan_container_windows_merges_grype_and_msrc_findings():
    """Grype findings and MSRC OS CVE findings are merged into the result."""
    fake_syft_json = {"artifacts": [], "distro": {}}
    grype_output = {
        "matches": [
            {
                "vulnerability": {
                    "id": "GHSA-gmc6-fwg3-75m5",
                    "severity": "High",
                    "cvss": [{"metrics": {"baseScore": 7.5}}],
                    "fix": {"state": "fixed", "versions": ["4.7.1"]},
                    "description": "MimeKit vulnerability",
                    "urls": [],
                },
                "artifact": {"name": "MimeKit", "version": "4.3.0.0", "type": "dotnet"},
            }
        ],
        "distro": {"name": "", "version": "", "idLike": None},
    }
    msrc_finding = {
        "vulnerability_id": "CVE-2026-21513",
        "package_name": "Windows OS (build 10.0.20348.4648)",
        "package_version": "10.0.20348.4648",
        "package_ecosystem": "windows-os",
        "severity": "HIGH",
        "cvss_score": 8.8,
        "description": "MSHTML Framework Security Feature Bypass Vulnerability",
        "fix_version": "10.0.20348.4773",
        "is_fixed": True,
        "reachable": False,
        "exploitable": False,
        "references": ["https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-21513"],
    }
    with patch("app.services.scanner._detect_image_platform", return_value="windows/amd64"), \
         patch("app.services.scanner._run_syft_json", return_value=fake_syft_json), \
         patch("app.services.scanner._run_grype_sbom", return_value=grype_output), \
         patch("app.services.msrc.scan_windows_os_cves", return_value=[msrc_finding]):
        findings, engine, _, _ = scan_container(
            "mcr.microsoft.com/windows/servercore:ltsc2022"
        )
    assert len(findings) == 2
    vuln_ids = {f["vulnerability_id"] for f in findings}
    assert "GHSA-gmc6-fwg3-75m5" in vuln_ids
    assert "CVE-2026-21513" in vuln_ids


def test_scan_container_windows_raises_unsupported_when_syft_fails():
    """scan_container raises WindowsImageUnsupportedError when Syft returns
    nothing for a Windows image (tool missing or registry unreachable)."""
    with patch("app.services.scanner._detect_image_platform", return_value="windows/amd64"), \
         patch("app.services.scanner._run_syft_json", return_value=None):
        with pytest.raises(WindowsImageUnsupportedError):
            scan_container("mcr.microsoft.com/windows/nanoserver:ltsc2022")


# ---------------------------------------------------------------------------
# MSRC matching tests
# ---------------------------------------------------------------------------

def _make_artifact(product_version: str, company: str = "Microsoft Corporation") -> dict:
    return {
        "type": "dotnet",
        "metadata": {
            "companyName": company,
            "productVersion": product_version,
        }
    }


def test_extract_windows_build_returns_highest_revision():
    """extract_windows_build picks the highest revision from Microsoft DLLs."""
    artifacts = [
        _make_artifact("10.0.20348.4648"),
        _make_artifact("10.0.20348.4773"),
        _make_artifact("10.0.20348.4050"),
    ]
    result = extract_windows_build(artifacts)
    assert result == (20348, 4773)


def test_extract_windows_build_ignores_non_microsoft():
    """Non-Microsoft DLLs are ignored even if they have 10.0.x.y versions."""
    artifacts = [
        _make_artifact("10.0.20348.4648", company="Acme Corp"),
        _make_artifact("10.0.20348.9999"),  # Microsoft — should be picked
    ]
    result = extract_windows_build(artifacts)
    assert result == (20348, 9999)


def test_extract_windows_build_returns_none_for_no_artifacts():
    assert extract_windows_build([]) is None
    assert extract_windows_build([_make_artifact("1.2.3.4")]) is None  # wrong prefix


def test_msrc_cve_matching_vulnerable():
    """_extract_cves_from_feed returns a finding when image revision < fixed revision."""
    feed = {
        "Vulnerability": [
            {
                "CVE": "CVE-2026-99999",
                "Title": {"Value": "Test OS Vulnerability"},
                "CVSSScoreSets": [{"BaseScore": 8.8}],
                "Threats": [],
                "Remediations": [
                    {
                        "Type": 1,
                        "ProductID": ["11923"],
                        "FixedBuild": "10.0.20348.5000",
                        "Description": {"Value": "KB9999999"},
                    }
                ],
            }
        ]
    }
    # Image is at revision 4773, fix requires 5000 → vulnerable
    findings = _extract_cves_from_feed(feed, {"11923"}, 20348, 4773)
    assert len(findings) == 1
    assert findings[0]["vulnerability_id"] == "CVE-2026-99999"
    assert findings[0]["severity"] == "HIGH"
    assert findings[0]["fix_version"] == "10.0.20348.5000"
    assert findings[0]["is_fixed"] is True


def test_msrc_cve_matching_already_patched():
    """_extract_cves_from_feed returns no finding when image revision >= fixed revision."""
    feed = {
        "Vulnerability": [
            {
                "CVE": "CVE-2026-11111",
                "Title": {"Value": "Already Patched"},
                "CVSSScoreSets": [{"BaseScore": 7.0}],
                "Threats": [],
                "Remediations": [
                    {
                        "Type": 1,
                        "ProductID": ["11923"],
                        "FixedBuild": "10.0.20348.4000",  # older than image
                        "Description": {"Value": "KB1111111"},
                    }
                ],
            }
        ]
    }
    findings = _extract_cves_from_feed(feed, {"11923"}, 20348, 4773)
    assert len(findings) == 0


def test_msrc_cve_matching_wrong_product():
    """_extract_cves_from_feed skips CVEs for different products."""
    feed = {
        "Vulnerability": [
            {
                "CVE": "CVE-2026-22222",
                "Title": {"Value": "Win10 Only"},
                "CVSSScoreSets": [{"BaseScore": 6.0}],
                "Threats": [],
                "Remediations": [
                    {
                        "Type": 1,
                        "ProductID": ["11929"],  # Win11 21H2, not Server 2022
                        "FixedBuild": "10.0.20348.5000",
                        "Description": {"Value": "KB2222222"},
                    }
                ],
            }
        ]
    }
    findings = _extract_cves_from_feed(feed, {"11923", "11924"}, 20348, 4773)
    assert len(findings) == 0


def test_scan_windows_os_cves_with_mocked_feed():
    """scan_windows_os_cves returns findings when MSRC feed has matching CVEs."""
    artifacts = [_make_artifact("10.0.20348.4648")]  # older than 4773 fix
    fake_feed = {
        "Vulnerability": [
            {
                "CVE": "CVE-2026-77777",
                "Title": {"Value": "Mock Windows CVE"},
                "CVSSScoreSets": [{"BaseScore": 9.1}],
                "Threats": [],
                "Remediations": [
                    {
                        "Type": 1,
                        "ProductID": ["11923"],
                        "FixedBuild": "10.0.20348.4773",
                        "Description": {"Value": "KB7777777"},
                    }
                ],
            }
        ]
    }
    with patch("app.services.msrc._fetch_feed", return_value=fake_feed):
        findings = scan_windows_os_cves(artifacts)
    assert len(findings) == 1
    assert findings[0]["vulnerability_id"] == "CVE-2026-77777"
    assert findings[0]["severity"] == "CRITICAL"  # 9.1 >= 9.0


def test_scan_container_uses_grype_when_trivy_absent(tmp_path):
    """scan_container should fall back to Grype when Trivy is not available."""
    grype_output = {
        "matches": [
            {
                "vulnerability": {
                    "id": "CVE-2023-9999",
                    "severity": "High",
                    "cvss": [{"metrics": {"baseScore": 7.5}}],
                    "fix": {"versions": ["2.0.0"], "state": "fixed"},
                    "description": "A test vulnerability",
                    "urls": ["https://example.com/CVE-2023-9999"],
                },
                "artifact": {
                    "name": "requests",
                    "version": "2.25.0",
                    "type": "python",
                },
            }
        ]
    }
    with patch("app.services.scanner._run_trivy_json", return_value=None), \
         patch("app.services.scanner._run_grype_json", return_value=grype_output), \
         patch("app.services.scanner._detect_image_platform", return_value="linux/amd64"):
        findings, engine, base_image, chain = scan_container("myimage:latest")
    assert len(findings) == 1
    assert findings[0]["vulnerability_id"] == "CVE-2023-9999"
    assert findings[0]["package_name"] == "requests"


# ---------------------------------------------------------------------------
# Grype JSON parsing tests
# ---------------------------------------------------------------------------

SAMPLE_GRYPE_JSON = {
    "matches": [
        {
            "vulnerability": {
                "id": "CVE-2023-1234",
                "severity": "High",
                "cvss": [
                    {"metrics": {"baseScore": 7.5}},
                    {"metrics": {"baseScore": 6.0}},
                ],
                "fix": {"versions": ["2.28.0"], "state": "fixed"},
                "description": "SSRF vulnerability in requests",
                "urls": ["https://example.com/cve-2023-1234"],
            },
            "artifact": {
                "name": "requests",
                "version": "2.25.0",
                "type": "python",
            },
        },
        {
            "vulnerability": {
                "id": "CVE-2023-5678",
                "severity": "Medium",
                "cvss": [{"metrics": {"baseScore": 5.3}}],
                "fix": {"versions": [], "state": "not-fixed"},
                "description": "XSS in lodash",
                "urls": [],
            },
            "artifact": {
                "name": "lodash",
                "version": "4.17.20",
                "type": "javascript",
            },
        },
        {
            "vulnerability": {
                "id": "CVE-2023-0001",
                "severity": "Critical",
                "cvss": [],
                "fix": {"versions": [], "state": "unknown"},
                "description": "OS-level vuln",
                "urls": [],
            },
            "artifact": {
                "name": "libc6",
                "version": "2.31",
                "type": "deb",
            },
        },
    ]
}


def test_grype_results_to_findings_count():
    """All Grype matches become findings regardless of artifact type."""
    findings = _grype_results_to_findings(SAMPLE_GRYPE_JSON)
    assert len(findings) == 3


def test_grype_results_to_findings_severity():
    findings = _grype_results_to_findings(SAMPLE_GRYPE_JSON)
    sevs = {f["vulnerability_id"]: f["severity"] for f in findings}
    assert sevs["CVE-2023-1234"] == "HIGH"
    assert sevs["CVE-2023-5678"] == "MEDIUM"
    assert sevs["CVE-2023-0001"] == "CRITICAL"


def test_grype_results_to_findings_highest_cvss():
    """The highest base score across multiple CVSS entries should be chosen."""
    findings = _grype_results_to_findings(SAMPLE_GRYPE_JSON)
    req_finding = next(f for f in findings if f["vulnerability_id"] == "CVE-2023-1234")
    assert req_finding["cvss_score"] == 7.5


def test_grype_results_to_findings_fix_version():
    findings = _grype_results_to_findings(SAMPLE_GRYPE_JSON)
    req_finding = next(f for f in findings if f["vulnerability_id"] == "CVE-2023-1234")
    assert req_finding["fix_version"] == "2.28.0"
    assert req_finding["is_fixed"] is True

    lodash_finding = next(f for f in findings if f["vulnerability_id"] == "CVE-2023-5678")
    assert lodash_finding["fix_version"] is None
    assert lodash_finding["is_fixed"] is False


def test_grype_results_to_findings_ecosystem_mapping():
    findings = _grype_results_to_findings(SAMPLE_GRYPE_JSON)
    req_finding = next(f for f in findings if f["package_name"] == "requests")
    assert req_finding["package_ecosystem"] == "PyPI"

    lodash_finding = next(f for f in findings if f["package_name"] == "lodash")
    assert lodash_finding["package_ecosystem"] == "npm"


def test_grype_results_to_findings_empty():
    assert _grype_results_to_findings({}) == []
    assert _grype_results_to_findings({"matches": []}) == []
