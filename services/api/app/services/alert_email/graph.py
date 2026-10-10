"""Sending mail through Microsoft Graph with the client-credentials flow (an Entra app registration with the APPLICATION permission Mail.Send).

Every failure is classified, because the caller reacts to it differently: PERMANENT (the credentials or permissions are wrong: 400/401/403/404, a refused token request) will not fix itself, so the worker keeps the alerts pending, shows the error to the platform administrator
and tries again each cycle in case the setup is corrected; TRANSIENT (throttling 429, 5xx, a network error or timeout) is simply retried later, honouring Retry-After. A 401 on the send itself is retried ONCE with a fresh token (a cached token can have been revoked).

The client secret never appears in a message, a log line or an exception: every error text is scrubbed of it and truncated. The access token is cached in memory until a minute before it expires.

This could not be tested against a real Microsoft tenant here: it is tested against a mock Graph (httpx's MockTransport and a local stand-in server), so the first real send should be done with the platform setting's "send a test email".
"""
from __future__ import annotations

import time
from collections.abc import Callable
from typing import Any
from urllib.parse import quote

import httpx

from app.core.config import settings

GRAPH_SCOPE = "https://graph.microsoft.com/.default"
_TOKEN_REFRESH_MARGIN_SECONDS = 60
_TRANSIENT_STATUSES = frozenset({408, 429, 500, 502, 503, 504})
_MAX_ERROR_CHARS = 240


class MailError(Exception):
    """A send that did not happen. `permanent` says whether retrying can help; `retry_after` is the server's hint in seconds."""

    def __init__(self, message: str, *, permanent: bool, retry_after: float | None = None) -> None:
        super().__init__(message)
        self.permanent = permanent
        self.retry_after = retry_after


def scrub(text: str, secrets: tuple[str, ...]) -> str:
    """The text with every secret replaced, whitespace collapsed and the length limited: safe to store and to show."""
    for secret in secrets:
        if secret:
            text = text.replace(secret, "***")
    text = " ".join(text.split())
    return text if len(text) <= _MAX_ERROR_CHARS else text[: _MAX_ERROR_CHARS - 3] + "..."


def _retry_after(response: httpx.Response) -> float | None:
    try:
        value = float(response.headers.get("Retry-After", ""))
    except ValueError:
        return None
    return value if 0 <= value <= 3600 else None


def _graph_error(response: httpx.Response, secrets: tuple[str, ...]) -> str:
    code = message = ""
    try:
        err = response.json().get("error", {})
        if isinstance(err, dict):
            code, message = str(err.get("code", "")), str(err.get("message", ""))
        elif isinstance(err, str):
            code, message = err, str(response.json().get("error_description", ""))
    except Exception:  # noqa: BLE001  # not JSON: say only the status
        pass
    return scrub(f"HTTP {response.status_code} {code} {message}".strip(), secrets)


class GraphMailer:
    def __init__(
        self,
        *,
        tenant_id: str,
        client_id: str,
        client_secret: str,
        sender: str,
        base_url: str = "https://graph.microsoft.com/v1.0",
        authority: str = "https://login.microsoftonline.com",
        timeout: float = 15.0,
        client: httpx.AsyncClient | None = None,
        monotonic: Callable[[], float] = time.monotonic,
    ) -> None:
        self.tenant_id, self.client_id, self.client_secret, self.sender = tenant_id, client_id, client_secret, sender
        self.base_url, self.authority, self.timeout = base_url.rstrip("/"), authority.rstrip("/"), timeout
        self._client, self._monotonic = client, monotonic
        self._token_value: str | None = None
        self._token_expires: float = 0.0

    @classmethod
    def from_settings(cls, **overrides: Any) -> GraphMailer:
        return cls(
            tenant_id=settings.ALERT_EMAIL_GRAPH_TENANT_ID,
            client_id=settings.ALERT_EMAIL_GRAPH_CLIENT_ID,
            client_secret=settings.ALERT_EMAIL_GRAPH_CLIENT_SECRET,
            sender=settings.ALERT_EMAIL_SENDER,
            base_url=settings.ALERT_EMAIL_GRAPH_BASE_URL,
            authority=settings.ALERT_EMAIL_AUTHORITY,
            **overrides,
        )

    @property
    def configured(self) -> bool:
        return all((self.tenant_id, self.client_id, self.client_secret, self.sender))

    @property
    def _secrets(self) -> tuple[str, ...]:
        return (self.client_secret, self._token_value or "")

    async def _request(self, method: str, url: str, **kw: Any) -> httpx.Response:
        try:
            if self._client is not None:
                return await self._client.request(method, url, timeout=self.timeout, **kw)
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                return await client.request(method, url, **kw)
        except httpx.HTTPError as exc:
            raise MailError(f"network error talking to Microsoft ({type(exc).__name__})", permanent=False) from None

    async def _token(self, *, force: bool = False) -> str:
        if not force and self._token_value and self._monotonic() < self._token_expires:
            return self._token_value
        response = await self._request(
            "POST",
            f"{self.authority}/{quote(self.tenant_id, safe='')}/oauth2/v2.0/token",
            data={"client_id": self.client_id, "client_secret": self.client_secret, "scope": GRAPH_SCOPE, "grant_type": "client_credentials"},
        )
        if response.status_code != 200:
            transient = response.status_code in _TRANSIENT_STATUSES
            raise MailError(f"Microsoft refused the token request: {_graph_error(response, self._secrets)}", permanent=not transient, retry_after=_retry_after(response))
        try:
            body = response.json()
            token, lifetime = str(body["access_token"]), float(body.get("expires_in", 3600))
        except (ValueError, KeyError, TypeError):
            raise MailError("Microsoft's token response was not understood", permanent=False) from None
        self._token_value = token
        self._token_expires = self._monotonic() + max(0.0, lifetime - _TOKEN_REFRESH_MARGIN_SECONDS)
        return token

    async def send(self, to: list[str], subject: str, text: str) -> None:
        """Send one plain-text message from the configured mailbox. Raises MailError (see the module docstring); returns None when Microsoft accepted it."""
        if not self.configured:
            raise MailError("Microsoft Graph credentials are not configured (ALERT_EMAIL_GRAPH_* and ALERT_EMAIL_SENDER)", permanent=True)
        if not to:
            raise MailError("no recipients", permanent=True)
        payload = {
            "message": {"subject": subject, "body": {"contentType": "Text", "content": text}, "toRecipients": [{"emailAddress": {"address": a}} for a in to]},
            "saveToSentItems": False,
        }
        url = f"{self.base_url}/users/{quote(self.sender, safe='@')}/sendMail"
        for attempt in (1, 2):
            token = await self._token(force=attempt == 2)
            response = await self._request("POST", url, json=payload, headers={"Authorization": f"Bearer {token}"})
            if response.status_code == 202:
                return
            if response.status_code == 401 and attempt == 1:
                continue  # a cached token can have been revoked: one retry with a fresh one
            transient = response.status_code in _TRANSIENT_STATUSES
            raise MailError(f"Microsoft Graph refused the message: {_graph_error(response, self._secrets)}", permanent=not transient, retry_after=_retry_after(response))
        raise MailError("unreachable", permanent=True)  # pragma: no cover
