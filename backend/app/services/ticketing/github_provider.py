"""GitHub Issues ticketing provider."""
from __future__ import annotations

import logging
from typing import Any

import httpx

from .base import ConnectionTestResult, TicketCreateResult, TicketingProvider

logger = logging.getLogger(__name__)


class GitHubIssuesProvider(TicketingProvider):
    """Ticketing provider for GitHub Issues.

    Uses the GitHub REST API (v2022-11-28).
    Expects ``provider_config`` to contain ``owner`` and ``repo``.
    Auth is via Personal Access Token (Bearer header).
    """

    def __init__(
        self,
        base_url: str,
        auth_method: str,
        username: str | None,
        secret: str | None,
        provider_config: dict[str, Any],
    ) -> None:
        self.base_url = base_url.rstrip("/") or "https://api.github.com"
        self.auth_method = auth_method
        self.username = username
        self.secret = secret
        self.config = provider_config
        self.owner = provider_config.get("owner", "")
        self.repo = provider_config.get("repo", "")
        self._client = self._build_client()

    def close(self) -> None:
        """Close the underlying HTTP client."""
        self._client.close()

    def __enter__(self) -> "GitHubIssuesProvider":
        return self

    def __exit__(self, *exc: Any) -> None:
        self.close()

    def _build_client(self) -> httpx.Client:
        headers = {
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        }
        if self.secret:
            headers["Authorization"] = f"Bearer {self.secret}"
        return httpx.Client(
            base_url=self.base_url,
            headers=headers,
            timeout=30.0,
        )

    def _repo_path(self) -> str:
        return f"/repos/{self.owner}/{self.repo}"

    def test_connection(self) -> ConnectionTestResult:
        try:
            # Verify auth
            user_resp = self._client.get("/user")
            if user_resp.status_code != 200:
                return ConnectionTestResult(
                    success=False,
                    message=f"Authentication failed: {user_resp.status_code} {user_resp.text[:200]}",
                )
            user_login = user_resp.json().get("login", "unknown")

            # Verify repo access
            repo_resp = self._client.get(self._repo_path())
            if repo_resp.status_code != 200:
                return ConnectionTestResult(
                    success=False,
                    message=f"Repository {self.owner}/{self.repo} not found or inaccessible",
                )

            # List user repos as "projects" for UI display
            repos_resp = self._client.get("/user/repos", params={"per_page": 30, "sort": "updated"})
            projects = None
            if repos_resp.status_code == 200:
                projects = [
                    {"key": r["full_name"], "name": r.get("description") or r["name"]}
                    for r in repos_resp.json()
                ]

            return ConnectionTestResult(
                success=True,
                message=f"Connected as {user_login} — repo {self.owner}/{self.repo} accessible",
                projects=projects,
            )
        except httpx.HTTPError as exc:
            return ConnectionTestResult(success=False, message=str(exc))

    def create_ticket(self, fields: dict[str, Any]) -> TicketCreateResult:
        payload: dict[str, Any] = {
            "title": fields.get("summary", "Untitled"),
        }
        if fields.get("description"):
            payload["body"] = fields["description"]
        if fields.get("labels"):
            payload["labels"] = fields["labels"]
        if fields.get("assignees"):
            payload["assignees"] = fields["assignees"]

        resp = self._client.post(f"{self._repo_path()}/issues", json=payload)
        resp.raise_for_status()
        data = resp.json()
        number = data["number"]
        return TicketCreateResult(
            external_id=str(number),
            external_key=f"{self.owner}/{self.repo}#{number}",
            external_url=data["html_url"],
            summary=fields.get("summary", ""),
        )

    def get_ticket_status(self, external_id: str) -> str | None:
        try:
            resp = self._client.get(f"{self._repo_path()}/issues/{external_id}")
            if resp.status_code != 200:
                return None
            return resp.json().get("state")  # "open" or "closed"
        except httpx.HTTPError:
            return None

    def transition_ticket(self, external_id: str, transition_name: str) -> str | None:
        """Transition a GitHub issue to open or closed.

        Accepts transition names: "open", "closed", "close", "reopen".
        Returns the canonical state string ("open" or "closed") on success, None on failure.
        """
        state_map = {
            "open": "open",
            "reopen": "open",
            "reopened": "open",
            "close": "closed",
            "closed": "closed",
            "done": "closed",
            "resolved": "closed",
        }
        target_state = state_map.get(transition_name.lower())
        if not target_state:
            logger.warning("Unknown GitHub transition '%s'", transition_name)
            return None
        try:
            resp = self._client.patch(
                f"{self._repo_path()}/issues/{external_id}",
                json={"state": target_state},
            )
            return target_state if resp.status_code == 200 else None
        except httpx.HTTPError:
            return None

    def add_comment(self, external_id: str, body: str) -> str | None:
        try:
            resp = self._client.post(
                f"{self._repo_path()}/issues/{external_id}/comments",
                json={"body": body},
            )
            if resp.status_code in (200, 201):
                return str(resp.json().get("id"))
            return None
        except httpx.HTTPError:
            return None

    def update_fields(self, external_id: str, fields: dict[str, Any]) -> bool:
        """Update fields on a GitHub issue (title, body, labels, assignees, state)."""
        try:
            resp = self._client.patch(
                f"{self._repo_path()}/issues/{external_id}",
                json=fields,
            )
            return resp.status_code == 200
        except httpx.HTTPError:
            return False

    def get_issue_detail(self, external_id: str) -> dict[str, Any] | None:
        try:
            resp = self._client.get(f"{self._repo_path()}/issues/{external_id}")
            if resp.status_code != 200:
                return None
            return resp.json()
        except httpx.HTTPError:
            return None

    def register_webhook(
        self,
        callback_url: str,
        events: list[str],
        **kwargs: Any,
    ) -> dict[str, Any]:
        """Register a webhook on the GitHub repository."""
        # Default events if none provided
        if not events:
            events = ["issues", "issue_comment"]

        payload = {
            "name": "web",
            "active": True,
            "events": events,
            "config": {
                "url": callback_url,
                "content_type": "json",
            },
        }
        secret = kwargs.get("secret")
        if secret:
            payload["config"]["secret"] = secret

        try:
            resp = self._client.post(
                f"{self._repo_path()}/hooks",
                json=payload,
            )
            if resp.status_code in (200, 201):
                data = resp.json()
                return {
                    "success": True,
                    "external_webhook_id": str(data["id"]),
                    "message": "Webhook registered successfully",
                }
            return {
                "success": False,
                "external_webhook_id": None,
                "message": f"Failed: {resp.status_code} {resp.text[:300]}",
            }
        except httpx.HTTPError as exc:
            return {
                "success": False,
                "external_webhook_id": None,
                "message": str(exc),
            }

    def deregister_webhook(self, external_webhook_id: str) -> bool:
        try:
            resp = self._client.delete(
                f"{self._repo_path()}/hooks/{external_webhook_id}",
            )
            return resp.status_code in (200, 204)
        except httpx.HTTPError:
            return False
