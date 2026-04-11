from __future__ import annotations

import abc
from dataclasses import dataclass
from typing import Any


@dataclass
class TicketCreateResult:
    external_id: str
    external_key: str
    external_url: str
    summary: str


@dataclass
class ConnectionTestResult:
    success: bool
    message: str
    projects: list[dict[str, str]] | None = None


@dataclass
class WebhookRegistrationResult:
    external_webhook_id: str | None
    success: bool
    message: str


class TicketingProvider(abc.ABC):
    @abc.abstractmethod
    def test_connection(self) -> ConnectionTestResult: ...

    @abc.abstractmethod
    def create_ticket(self, fields: dict[str, Any]) -> TicketCreateResult: ...

    @abc.abstractmethod
    def get_ticket_status(self, external_id: str) -> str | None: ...

    @abc.abstractmethod
    def transition_ticket(self, external_id: str, transition_name: str) -> str | None:
        """Transition a ticket. Returns the canonical status string on success, None on failure."""
        ...

    @abc.abstractmethod
    def add_comment(self, external_id: str, body: str) -> str | None: ...

    @abc.abstractmethod
    def get_issue_detail(self, external_id: str) -> dict[str, Any] | None: ...

    # Optional methods with default implementations — override as needed
    def update_fields(self, external_id: str, fields: dict[str, Any]) -> bool:
        """Update fields on an external ticket. Returns True on success."""
        return False

    def register_webhook(
        self, callback_url: str, events: list[str], **kwargs: Any
    ) -> dict[str, Any]:
        """Register a webhook with the external provider."""
        raise NotImplementedError(f"{type(self).__name__} does not support webhook registration")

    def deregister_webhook(self, external_webhook_id: str) -> bool:
        """Deregister a webhook from the external provider."""
        raise NotImplementedError(f"{type(self).__name__} does not support webhook deregistration")
