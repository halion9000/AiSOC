#!/usr/bin/env python3
"""Call the data endpoints behind AiSOC's main pages as a signed-in caller and report which fail or are slow.

Why: some failures only show on the real stack, with real data (a page whose list call takes ten seconds and exhausts the database pool; an API that crashes on start). This asks for every
page's data the way the console does and says plainly which answered, which did not and how long each took.

    python scripts/smoke-api.py --base http://localhost:8000 --token <an AiSOC API key or access token>
    AISOC_SMOKE_TOKEN=... python scripts/smoke-api.py            # the same, with the token from the environment

Exit status: 0 when every endpoint answered 2xx within the slow limit, 1 when any failed (5xx, 4xx, no answer) or was slower than --slow seconds (default 8), 2 for a usage error.
Read-only: it only sends GET requests. The token is never printed.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
import urllib.error
import urllib.request

# (name, path): what each page of the console asks for first.
ENDPOINTS: list[tuple[str, str]] = [
    ("alerts list", "/api/v1/alerts?page=1&page_size=25"),
    ("alert queue", "/api/v1/alerts/queue?limit=25"),
    ("entities queue", "/api/v1/fusion/entity-risk/queue?limit=25"),
    ("entities stats", "/api/v1/fusion/entity-risk/stats"),
    ("devices", "/api/v1/devices?page=1&page_size=50"),
    ("devices by client", "/api/v1/devices/rollup"),
    ("possible duplicates", "/api/v1/devices/duplicates"),
    ("cases", "/api/v1/cases?page=1&page_size=25"),
    ("platform health", "/api/v1/health/services"),
    ("pipeline health", "/api/v1/health/pipeline"),
    ("compliance frameworks", "/api/v1/compliance/frameworks"),
    ("honeytokens", "/api/v1/honeytokens"),
    ("threat intel", "/api/v1/threat-intel/iocs?limit=25"),
    ("clients", "/api/v1/mssp/children"),
    ("connectors", "/api/v1/connectors"),
    ("ticket settings", "/api/v1/tenant-settings/tickets"),
    ("auto-close settings", "/api/v1/tenant-settings/auto-close"),
]


def classify(status: int | None, seconds: float, slow: float) -> str:
    """ok, slow (answered but past the limit), or failed (an error status, or no answer at all)."""
    if status is None or status >= 400:
        return "failed"
    return "slow" if seconds > slow else "ok"


def fetch(base: str, path: str, token: str, timeout: float) -> tuple[int | None, float, str]:
    request = urllib.request.Request(base.rstrip("/") + path, headers={"Authorization": f"Bearer {token}", "Accept": "application/json"})
    started = time.monotonic()
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            response.read(1)
            return response.status, time.monotonic() - started, ""
    except urllib.error.HTTPError as err:
        detail = ""
        try:
            detail = str(json.loads(err.read().decode("utf-8", "replace")).get("detail", ""))[:120]
        except Exception:  # noqa: BLE001
            pass
        return err.code, time.monotonic() - started, detail
    except Exception as err:  # noqa: BLE001 - no answer at all
        return None, time.monotonic() - started, type(err).__name__


def run(base: str, token: str, slow: float, timeout: float, endpoints: list[tuple[str, str]] = ENDPOINTS, get=fetch) -> list[dict]:
    results = []
    for name, path in endpoints:
        status, seconds, detail = get(base, path, token, timeout)
        results.append({"name": name, "path": path, "status": status, "seconds": round(seconds, 2), "detail": detail, "verdict": classify(status, seconds, slow)})
    return results


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--base", default=os.environ.get("AISOC_SMOKE_BASE", "http://localhost:8000"))
    parser.add_argument("--token", default=os.environ.get("AISOC_SMOKE_TOKEN", ""))
    parser.add_argument("--slow", type=float, default=8.0, help="seconds after which an answer counts as slow")
    parser.add_argument("--timeout", type=float, default=60.0)
    args = parser.parse_args(argv)
    if not args.token:
        print("Give a token with --token or AISOC_SMOKE_TOKEN.", file=sys.stderr)
        return 2
    results = run(args.base, args.token, args.slow, args.timeout)
    for r in results:
        mark = {"ok": "ok    ", "slow": "SLOW  ", "failed": "FAILED"}[r["verdict"]]
        print(f"{mark} {r['status'] if r['status'] is not None else '---'}  {r['seconds']:>6.2f}s  {r['name']}  ({r['path']}){'  ' + r['detail'] if r['detail'] and r['verdict'] != 'ok' else ''}")
    bad = [r for r in results if r["verdict"] != "ok"]
    print(f"\n{len(results) - len(bad)} of {len(results)} answered well." + (f" Look at: {', '.join(r['name'] for r in bad)}." if bad else ""))
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
