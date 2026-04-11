from __future__ import annotations

from typing import Any


def compute_risk_score(
    cvss_score: float | None,
    severity: str,
    exploitable: bool,
    reachable: bool,
    epss_score: float | None = None,
) -> float:
    """Return a normalised 0-10 risk score.

    Multipliers applied in order:
    - exploitable flag: u00d71.5
    - reachable flag:   u00d71.3
    - EPSS u2265 0.1:       u00d71.4  (high real-world exploitation probability)
    - EPSS u2265 0.5:       u00d71.6  (very high; replaces the 1.4 multiplier)
    """
    _severity_base: dict[str, float] = {
        "CRITICAL": 9.0,
        "HIGH": 7.0,
        "MEDIUM": 4.0,
        "LOW": 1.0,
        "UNKNOWN": 2.0,
    }
    base = cvss_score if cvss_score is not None else _severity_base.get(severity.upper(), 2.0)

    score = base
    if exploitable:
        score *= 1.5
    if reachable:
        score *= 1.3
    if epss_score is not None:
        if epss_score >= 0.5:
            score *= 1.6
        elif epss_score >= 0.1:
            score *= 1.4

    return round(min(score, 10.0), 2)


def prioritize_findings(findings: list[Any]) -> list[Any]:
    """Return findings sorted by risk_score descending."""
    return sorted(findings, key=lambda f: f.risk_score, reverse=True)
