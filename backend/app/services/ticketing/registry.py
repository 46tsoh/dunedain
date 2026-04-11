from __future__ import annotations

from typing import Any

from .base import TicketingProvider
from .github_provider import GitHubIssuesProvider
from .jira_provider import JiraProvider

_PROVIDERS: dict[str, type] = {
    "jira": JiraProvider,
    "github_issues": GitHubIssuesProvider,
}


def get_provider(
    provider: str,
    base_url: str,
    auth_method: str,
    username: str | None,
    secret: str | None,
    provider_config: dict[str, Any],
) -> TicketingProvider:
    cls = _PROVIDERS.get(provider)
    if cls is None:
        raise ValueError(
            f"Unsupported ticketing provider '{provider}'. "
            f"Supported: {', '.join(sorted(_PROVIDERS))}"
        )
    return cls(
        base_url=base_url,
        auth_method=auth_method,
        username=username,
        secret=secret,
        provider_config=provider_config,
    )
