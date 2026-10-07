"""Credentials for the API's own calls to other AiSOC services.

The agents service requires authentication in production (see its
app/core/service_auth.py). When the API proxies a request it has ALREADY
authenticated the user itself, so it vouches for the call with the shared
internal token rather than forwarding user credentials. Compose wires the same
secret to the API (REALTIME_INTERNAL_TOKEN) and to agents/realtime
(INTERNAL_TOKEN). In development the token is empty and nothing is sent.
"""
import os

from app.core.config import settings


def internal_service_headers() -> dict[str, str]:
    token = (settings.REALTIME_INTERNAL_TOKEN or "").strip()
    return {"x-internal-token": token} if token else {}


def connectors_service_headers() -> dict[str, str]:
    """Credentials for the API's calls to the connectors service (its only caller).

    That service makes outbound calls using connector configuration and decrypted credentials supplied in each
    request, and requires ``Authorization: Bearer <AISOC_CONNECTORS_SERVICE_TOKEN>`` (see
    services/connectors/app/security/service_auth.py). Empty when no token is configured (development).
    """
    token = (os.getenv("AISOC_CONNECTORS_SERVICE_TOKEN") or "").strip()
    return {"Authorization": f"Bearer {token}"} if token else {}


def fusion_service_headers() -> dict[str, str]:
    """Credentials for the API's calls to the fusion service (``Authorization: Bearer <AISOC_FUSION_SERVICE_TOKEN>``)."""
    token = (os.getenv("AISOC_FUSION_SERVICE_TOKEN") or "").strip()
    return {"Authorization": f"Bearer {token}"} if token else {}


def ingest_service_headers() -> dict[str, str]:
    """Credentials for calls to the ingest service (``Authorization: Bearer <AISOC_INGEST_SERVICE_TOKEN>``)."""
    token = (os.getenv("AISOC_INGEST_SERVICE_TOKEN") or "").strip()
    return {"Authorization": f"Bearer {token}"} if token else {}


def enrichment_service_headers() -> dict[str, str]:
    """Credentials for calls to the enrichment service (``Authorization: Bearer <AISOC_ENRICHMENT_SERVICE_TOKEN>``)."""
    token = (os.getenv("AISOC_ENRICHMENT_SERVICE_TOKEN") or "").strip()
    return {"Authorization": f"Bearer {token}"} if token else {}
