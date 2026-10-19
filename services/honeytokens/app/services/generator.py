"""Honeytoken generator — creates plausible-looking tokens of various types."""

from __future__ import annotations

import base64
import hashlib
import os
import re
import secrets
import string
import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

from app.core.config import settings


def _random_b64(n_bytes: int = 20) -> str:
    return base64.b64encode(os.urandom(n_bytes)).decode()


def _random_alphanum(length: int = 32) -> str:
    alphabet = string.ascii_letters + string.digits
    return "".join(secrets.choice(alphabet) for _ in range(length))


def _fake_aws_access_key() -> str:
    """Generate a fake AWS access key ID that looks real."""
    prefix = "AKIA"
    body = "".join(secrets.choice(string.ascii_uppercase + string.digits) for _ in range(16))
    return prefix + body


def _fake_aws_secret_key() -> str:
    return _random_b64(30)


TOKEN_GENERATORS: dict[str, Any] = {
    "aws_key": lambda: {
        "access_key_id": _fake_aws_access_key(),
        "secret_access_key": _fake_aws_secret_key(),
    },
    # "url" and "file" get their link once the token's id is known (see generate_token): the link IS the id, so a visit identifies the token.
    "url": lambda: {},
    "file": lambda: {
        "filename": f"backup_{_random_alphanum(8)}.zip",
        "checksum": hashlib.sha256(os.urandom(32)).hexdigest(),
    },
    "db_credential": lambda: {
        "username": f"svc_{_random_alphanum(8).lower()}",
        "password": _random_alphanum(24),
        "host": "db-internal.example.com",
    },
    "email": lambda: {
        "email": f"canary+{_random_alphanum(12).lower()}@example.com",
    },
    "dns": lambda: {
        "fqdn": f"{_random_alphanum(12).lower()}.canary.example.com",
    },
    "api_key": lambda: {
        "api_key": f"sk-{''.join(secrets.choice(string.hexdigits) for _ in range(40))}",
    },
    "custom": lambda: {
        "value": _random_alphanum(32),
    },
}


# What can really raise an alert today. A link calls AiSOC when opened. Everything else is a decoy value: nothing watches for it being used (an AWS key needs CloudTrail, a DNS name a name
# server, an e-mail address a mailbox, a database login that system's logs), so the page says so rather than letting someone plant one and believe it will alert.
DETECTS_ON_OPEN = {"url", "file"}


def canary_base_url() -> str:
    """The configured link address without a trailing slash; anything that is not an http(s) address falls back to the default."""
    value = (settings.canary_base_url or "").strip().rstrip("/")
    return value if re.fullmatch(r"https?://[^\s/]+(?::\d+)?(?:/[^\s]*)?", value) else "http://localhost:3000"


def canary_link(token_id: uuid.UUID) -> str:
    return f"{canary_base_url()}/api/v1/canary/{token_id}"


def generate_token(
    token_type: str,
    name: str,
    description: str | None,
    tenant_id: uuid.UUID,
    created_by: str | None,
    metadata: dict | None = None,
    ttl_days: int | None = None,
) -> dict:
    """Generate a new honeytoken record (not yet persisted)."""
    if token_type not in TOKEN_GENERATORS:
        raise ValueError(f"Unknown token_type '{token_type}'. Valid: {list(TOKEN_GENERATORS)}")

    token_data = TOKEN_GENERATORS[token_type]()
    token_id = uuid.uuid4()
    if token_type == "url":
        token_data["url"] = canary_link(token_id)
    elif token_type == "file":
        token_data["beacon_url"] = canary_link(token_id)  # put this link inside the document: opening it fires the alert
    ttl = ttl_days if ttl_days is not None else settings.token_ttl_days
    expires_at = datetime.now(UTC) + timedelta(days=ttl)
    detection = "link" if token_type in DETECTS_ON_OPEN else "none"

    return {
        "id": token_id,
        "tenant_id": tenant_id,
        "name": name,
        "description": description,
        "token_type": token_type,
        "token_value": str(token_data),
        "metadata_": {**(metadata or {}), "token_data": token_data, "detection": detection},
        "status": "active",
        "expires_at": expires_at,
        "created_by": created_by,
    }
