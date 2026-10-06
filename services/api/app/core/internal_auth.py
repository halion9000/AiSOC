"""Credentials for the API's own calls to other AiSOC services.

The agents service requires authentication in production (see its
app/core/service_auth.py). When the API proxies a request it has ALREADY
authenticated the user itself, so it vouches for the call with the shared
internal token rather than forwarding user credentials. Compose wires the same
secret to the API (REALTIME_INTERNAL_TOKEN) and to agents/realtime
(INTERNAL_TOKEN). In development the token is empty and nothing is sent.
"""
from app.core.config import settings


def internal_service_headers() -> dict[str, str]:
    token = (settings.REALTIME_INTERNAL_TOKEN or "").strip()
    return {"x-internal-token": token} if token else {}
