from __future__ import annotations

from typing import Any

import httpx

from .base import ConnectionTestResult, TicketCreateResult, TicketingProvider, WebhookRegistrationResult


class JiraProvider(TicketingProvider):
    def __init__(
        self,
        base_url: str,
        auth_method: str,
        username: str | None,
        secret: str | None,
        provider_config: dict[str, Any],
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.auth_method = auth_method
        self.username = username
        self.secret = secret
        self.config = provider_config
        self._client = self._build_client()

    def close(self) -> None:
        """Close the underlying HTTP client."""
        self._client.close()

    def __enter__(self) -> "JiraProvider":
        return self

    def __exit__(self, *exc: Any) -> None:
        self.close()

    def _build_client(self) -> httpx.Client:
        headers = {"Content-Type": "application/json", "Accept": "application/json"}
        auth = None
        if self.auth_method in ("basic", "api_token"):
            auth = (self.username or "", self.secret or "")
        elif self.auth_method == "pat":
            headers["Authorization"] = f"Bearer {self.secret}"
        return httpx.Client(
            base_url=f"{self.base_url}/rest/api/2",
            headers=headers,
            auth=auth,
            timeout=30.0,
        )

    def test_connection(self) -> ConnectionTestResult:
        try:
            resp = self._client.get("/myself")
            if resp.status_code != 200:
                return ConnectionTestResult(
                    success=False,
                    message=f"Authentication failed: {resp.status_code} {resp.text[:200]}",
                )
            proj_resp = self._client.get("/project", params={"maxResults": 50})
            projects = None
            if proj_resp.status_code == 200:
                projects = [
                    {"key": p["key"], "name": p["name"]}
                    for p in proj_resp.json()
                ]
            return ConnectionTestResult(
                success=True,
                message=f"Connected as {resp.json().get('displayName', 'unknown')}",
                projects=projects,
            )
        except httpx.HTTPError as exc:
            return ConnectionTestResult(success=False, message=str(exc))

    def create_ticket(self, fields: dict[str, Any]) -> TicketCreateResult:
        payload = {"fields": fields}
        resp = self._client.post("/issue", json=payload)
        resp.raise_for_status()
        data = resp.json()
        key = data["key"]
        issue_id = data["id"]
        url = f"{self.base_url}/browse/{key}"
        return TicketCreateResult(
            external_id=issue_id,
            external_key=key,
            external_url=url,
            summary=fields.get("summary", ""),
        )

    def get_ticket_status(self, external_id: str) -> str | None:
        try:
            resp = self._client.get(f"/issue/{external_id}", params={"fields": "status"})
            if resp.status_code != 200:
                return None
            return resp.json().get("fields", {}).get("status", {}).get("name")
        except httpx.HTTPError:
            return None

    def transition_ticket(self, external_id: str, transition_name: str) -> str | None:
        """Transition a Jira issue to a new status.

        Fetches available transitions, finds the one matching transition_name
        (case-insensitive), and executes it.
        Returns the transition name on success, None on failure.
        """
        try:
            # Get available transitions
            resp = self._client.get(f"/issue/{external_id}/transitions")
            if resp.status_code != 200:
                return None
            transitions = resp.json().get("transitions", [])
            target = None
            for t in transitions:
                if t["name"].lower() == transition_name.lower():
                    target = t
                    break
            if target is None:
                return None
            # Execute the transition
            resp = self._client.post(
                f"/issue/{external_id}/transitions",
                json={"transition": {"id": target["id"]}},
            )
            return target["name"] if resp.status_code == 204 else None
        except httpx.HTTPError:
            return None

    def add_comment(self, external_id: str, body: str) -> str | None:
        """Add a comment to a Jira issue. Returns the comment ID or None on failure."""
        try:
            resp = self._client.post(
                f"/issue/{external_id}/comment",
                json={"body": body},
            )
            if resp.status_code in (200, 201):
                return resp.json().get("id")
            return None
        except httpx.HTTPError:
            return None

    def update_fields(self, external_id: str, fields: dict[str, Any]) -> bool:
        """Update fields on a Jira issue."""
        try:
            resp = self._client.put(
                f"/issue/{external_id}",
                json={"fields": fields},
            )
            return resp.status_code == 204
        except httpx.HTTPError:
            return False

    def get_issue_detail(self, external_id: str) -> dict[str, Any] | None:
        """Fetch full issue details from Jira."""
        try:
            resp = self._client.get(f"/issue/{external_id}")
            if resp.status_code != 200:
                return None
            return resp.json()
        except httpx.HTTPError:
            return None

    def register_webhook(
        self,
        callback_url: str,
        events: list[str],
        *,
        jql_filter: str = "",
        **kwargs: Any,
    ) -> dict[str, Any]:
        """Register a webhook with Jira (Cloud REST API).

        Returns dict with 'success', 'external_webhook_id', 'message' keys.
        """
        payload = {
            "name": "Dunedain Security Platform",
            "url": callback_url,
            "events": events,
            "excludeBody": False,
        }
        if jql_filter:
            payload["filters"] = {"issue-related-events-section": jql_filter}
        try:
            resp = self._client.post(
                f"{self.base_url}/rest/webhooks/1.0/webhook",
                json=payload,
            )
            if resp.status_code in (200, 201):
                data = resp.json()
                return {
                    "success": True,
                    "external_webhook_id": str(data.get("self", data.get("id", ""))),
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
        """Deregister a webhook from Jira."""
        try:
            resp = self._client.delete(
                f"{self.base_url}/rest/webhooks/1.0/webhook/{external_webhook_id}",
            )
            return resp.status_code in (200, 204)
        except httpx.HTTPError:
            return False
