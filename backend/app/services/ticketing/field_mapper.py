from __future__ import annotations

import re
from typing import Any

from ...models import Finding, Scan, Integration, IntegrationFieldMapping

_SEVERITY_TO_PRIORITY: dict[str, str] = {
    "CRITICAL": "Highest",
    "HIGH": "High",
    "MEDIUM": "Medium",
    "LOW": "Low",
    "NEGLIGIBLE": "Lowest",
    "UNKNOWN": "Medium",
}

_SEVERITY_TO_LABELS: dict[str, str] = {
    "CRITICAL": "severity:critical",
    "HIGH": "severity:high",
    "MEDIUM": "severity:medium",
    "LOW": "severity:low",
    "NEGLIGIBLE": "severity:negligible",
    "UNKNOWN": "severity:unknown",
}


def _resolve_source(source: str, finding: Finding, scan: Scan) -> Any:
    if source == "_static":
        return None
    obj_map: dict[str, Any] = {"finding": finding, "scan": scan}
    parts = source.split(".", 1)
    if len(parts) != 2 or parts[0] not in obj_map:
        return None
    return getattr(obj_map[parts[0]], parts[1], None)


def _render_template(template: str, finding: Finding, scan: Scan) -> str:
    def replacer(match: re.Match) -> str:
        path = match.group(1).strip()
        val = _resolve_source(path, finding, scan)
        return str(val) if val is not None else ""
    return re.sub(r"\{\{(.+?)\}\}", replacer, template)


def build_ticket_fields(
    integration: Integration,
    mappings: list[IntegrationFieldMapping],
    finding: Finding,
    scan: Scan,
    overrides: dict[str, Any] | None = None,
) -> dict[str, Any]:
    fields: dict[str, Any] = {}

    config = integration.provider_config or {}
    if integration.provider == "jira":
        if "project_key" in config:
            fields["project"] = {"key": config["project_key"]}
        if "issue_type" in config:
            fields["issuetype"] = {"name": config["issue_type"]}
    elif integration.provider == "github_issues":
        default_labels = config.get("default_labels", [])
        if default_labels:
            fields["labels"] = list(default_labels)

    for m in mappings:
        value: Any = None

        if m.transform == "static_value":
            value = m.template_value
        elif m.transform == "template":
            value = _render_template(m.template_value or "", finding, scan)
        elif m.transform == "severity_to_priority":
            sev = getattr(finding, "severity", "UNKNOWN")
            priority_name = _SEVERITY_TO_PRIORITY.get(sev, "Medium")
            value = {"name": priority_name}
        elif m.transform == "severity_to_labels":
            sev = getattr(finding, "severity", "UNKNOWN")
            label = _SEVERITY_TO_LABELS.get(sev, "severity:unknown")
            existing_labels = fields.get("labels", [])
            if isinstance(existing_labels, list):
                existing_labels.append(label)
                value = existing_labels
            else:
                value = [label]
        elif m.transform == "append_label":
            raw = _resolve_source(m.source, finding, scan)
            existing = fields.get(m.target_field, [])
            if isinstance(existing, list):
                existing.append(str(raw) if raw else (m.template_value or ""))
                value = existing
            else:
                value = [str(raw) if raw else (m.template_value or "")]
        else:
            value = _resolve_source(m.source, finding, scan)

        if value is not None:
            fields[m.target_field] = value

    if overrides:
        fields.update(overrides)

    if "summary" not in fields:
        fields["summary"] = (
            f"[{finding.severity}] {finding.vulnerability_id} "
            f"in {finding.package_name}@{finding.package_version}"
        )

    if "description" not in fields and integration.provider == "github_issues":
        parts = [
            f"**Vulnerability:** {finding.vulnerability_id}",
            f"**Package:** {finding.package_name}@{finding.package_version}",
            f"**Severity:** {finding.severity}",
            f"**Ecosystem:** {finding.package_ecosystem}",
        ]
        if finding.cvss_score is not None:
            parts.append(f"**CVSS Score:** {finding.cvss_score}")
        if finding.fix_version:
            parts.append(f"**Fix Version:** {finding.fix_version}")
        if finding.description:
            parts.append(f"\n---\n{finding.description}")
        fields["description"] = "\n".join(parts)

    return fields
