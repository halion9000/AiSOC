"""A plain build of the web image must be the real product, not the public demo.

apps/web/Dockerfile used to default NEXT_PUBLIC_DEMO_MODE to "true" and to bake demo login credentials into the public JavaScript bundle by default (an auto-login
email and password). Anything that built the image without overriding them shipped the demo banner, an auto-login into a demo account, a read-only UI and the demo
credentials themselves. The stack only escaped because docker-compose.yml overrode the mode flag, and the credentials stayed in the bundle regardless.

All five defaults are now empty, compose blanks all five too, and the hosted demo (which DOES want them) passes its values explicitly as build args, which this test
also pins so that blanking the defaults cannot quietly break it.
"""
import re
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[3]
DOCKERFILE = (ROOT / "apps/web/Dockerfile").read_text(encoding="utf-8")
COMPOSE = yaml.safe_load((ROOT / "docker-compose.yml").read_text(encoding="utf-8"))
DEMO_ARGS = [
    "NEXT_PUBLIC_DEMO_MODE",
    "NEXT_PUBLIC_DEMO_DEEPLINK",
    "NEXT_PUBLIC_DEMO_BANNER",
    "NEXT_PUBLIC_DEMO_AUTOLOGIN_EMAIL",
    "NEXT_PUBLIC_DEMO_AUTOLOGIN_PASSWORD",
]


def _dockerfile_defaults() -> dict[str, str]:
    found = {}
    for m in re.finditer(r'^ARG (NEXT_PUBLIC_DEMO_\w+)=(?:"([^"]*)"|(\S*))\s*$', DOCKERFILE, re.M):
        found[m.group(1)] = m.group(2) if m.group(2) is not None else m.group(3)
    return found


@pytest.mark.parametrize("arg", DEMO_ARGS)
def test_every_demo_build_arg_defaults_to_empty(arg):
    defaults = _dockerfile_defaults()
    assert arg in defaults, f"{arg} is not declared in apps/web/Dockerfile"
    assert defaults[arg] == "", f"{arg} defaults to {defaults[arg]!r}: a plain build would ship the demo"


def test_no_demo_credentials_appear_in_the_dockerfile():
    for secret in ("tryaisoc.com", "aisoc-demo"):
        assert secret not in DOCKERFILE, f"{secret!r} is baked into the web image by default"


@pytest.mark.parametrize("arg", DEMO_ARGS)
def test_compose_blanks_every_demo_build_arg_too(arg):
    """Belt and braces: even if the Dockerfile default were ever changed back, the stack's own build stays clean."""
    args = COMPOSE["services"]["web"]["build"]["args"]
    assert arg in args, f"compose does not set {arg} for the web build"
    assert args[arg] in ("", None), f"compose sets {arg} to {args[arg]!r}"


def test_the_hosted_demo_still_passes_its_values_explicitly():
    """The hosted demo needs these ON; with the defaults now blank it must be the build that asks for them."""
    for workflow in (".github/workflows/release.yml", ".github/workflows/publish-images.yml"):
        text = (ROOT / workflow).read_text(encoding="utf-8")
        assert "NEXT_PUBLIC_DEMO_MODE=true" in text, f"{workflow} no longer passes the demo flag explicitly: the hosted demo build would silently lose it"
