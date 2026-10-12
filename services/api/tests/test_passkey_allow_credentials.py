"""`allowCredentials` for a named passkey sign-in is built from descriptor OBJECTS, not dicts.

`webauthn.options_to_json` reads `.id` from every entry, so the plain dicts the handler used to build crashed it (`AttributeError: 'dict' object has no attribute 'id'`):
signing in by name failed for every user who had a passkey registered, while a usernameless sign-in (no credentials listed) worked. Found by the real-Postgres passkey test
(tests/test_rls_passkeys_fail_closed_postgres.py) and reproduced without any database: this is the database-free guard, so an ordinary test run catches the regression.
"""

import base64
import json
from types import SimpleNamespace

import pytest

webauthn = pytest.importorskip("webauthn")

from app.api.v1.endpoints import passkeys  # noqa: E402


def b64(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def row(raw_id: bytes, transports):
    return SimpleNamespace(credential_id=b64(raw_id), transports=transports)


def structs():
    return passkeys._import_webauthn()[1]  # noqa: SLF001


def options_json(*rows):
    descriptors = [passkeys._credential_descriptor(structs(), r) for r in rows]  # noqa: SLF001
    return json.loads(
        webauthn.options_to_json(webauthn.generate_authentication_options(rp_id="localhost", allow_credentials=descriptors or None))
    )


def test_the_descriptors_serialize_and_carry_the_credential_id_and_transports():
    out = options_json(row(b"credential-one", ["usb", "internal"]), row(b"credential-two", None))
    allowed = out["allowCredentials"]
    assert [a["id"] for a in allowed] == [b64(b"credential-one"), b64(b"credential-two")]
    assert allowed[0]["transports"] == ["usb", "internal"] and "transports" not in allowed[1]
    assert all(a["type"] == "public-key" for a in allowed)


def test_an_unrecognised_transport_hint_is_dropped_not_fatal():
    out = options_json(row(b"credential-x", ["usb", "telepathy"]))
    assert out["allowCredentials"][0]["transports"] == ["usb"]


def test_a_credential_with_only_unrecognised_transports_has_none_listed():
    assert "transports" not in options_json(row(b"credential-y", ["telepathy"]))["allowCredentials"][0]


def test_the_old_dict_form_is_what_crashed_the_serializer():
    """The control: it proves the test above would have caught the original bug."""
    options = webauthn.generate_authentication_options(
        rp_id="localhost", allow_credentials=[{"id": b"x", "type": "public-key", "transports": None}]
    )
    with pytest.raises(AttributeError, match="'dict' object has no attribute 'id'"):
        webauthn.options_to_json(options)
