"""Tokens survive the python-jose -> PyJWT migration, in BOTH directions, and PyJWT refuses what must be refused.

WHY: `python-jose` (and `ecdsa`, which it pulls in unconditionally) carry advisories with no fix (PYSEC-2026-1325, CVE-2026-85394). The
API used python-jose for its own access/refresh/realtime tokens and PyJWT for SAML/OIDC. Swapping the library under authentication is only
safe if (1) a token that python-jose minted BEFORE the deploy still verifies afterwards (sessions in flight), and (2) a token minted by
the NEW code still verifies on the OLD image if the deploy is rolled back. Both are plain HS256 JWS, so they should; this proves it with
the real claim shapes instead of assuming.
The cross-library tests need python-jose to be installed to MINT or READ the other side, so they skip where it is not (it is no longer a
dependency of the API); the PyJWT-only tests below always run. Claim shapes mirror app.core.security: `sub` is str(user.id), `exp` a
datetime, `type`, and a hex `jti`.
"""

import uuid
from datetime import UTC, datetime, timedelta

import jwt as pyjwt
import pytest

KEY = "k" * 48
ALG = "HS256"


def _claims(**over):
    base = {
        "sub": str(uuid.uuid4()),
        "tenant_id": str(uuid.uuid4()),
        "role": "analyst",
        "type": "access",
        "jti": uuid.uuid4().hex,
        "exp": datetime.now(UTC) + timedelta(minutes=30),
    }
    base.update(over)
    return base


def _jose():
    return pytest.importorskip(
        "jose.jwt", reason="python-jose is no longer an API dependency; this cross-library check runs where it is installed"
    )


def test_a_token_minted_by_python_jose_before_the_deploy_still_verifies_under_pyjwt():
    jose_jwt = _jose()
    for kind in ("access", "refresh"):
        claims = _claims(type=kind)
        expected_exp = int(claims["exp"].timestamp())  # python-jose MUTATES the dict it is given (datetime -> int), so read this first
        token = jose_jwt.encode(claims, KEY, algorithm=ALG)
        decoded = pyjwt.decode(token, KEY, algorithms=[ALG])
        assert decoded["sub"] == claims["sub"] and decoded["type"] == kind and decoded["jti"] == claims["jti"]
        assert decoded["exp"] == expected_exp


def test_a_token_minted_by_pyjwt_still_verifies_under_python_jose_so_a_rollback_keeps_sessions_alive():
    jose_jwt = _jose()
    claims = _claims()
    token = pyjwt.encode(claims, KEY, algorithm=ALG)
    assert isinstance(token, str), "PyJWT 2.x returns str, as python-jose does"
    decoded = jose_jwt.decode(token, KEY, algorithms=[ALG])
    assert decoded["sub"] == claims["sub"] and decoded["jti"] == claims["jti"]


def test_the_realtime_ticket_shape_round_trips_across_the_libraries():
    jose_jwt = _jose()
    ticket = {
        "sub": str(uuid.uuid4()),
        "tenant_id": str(uuid.uuid4()),
        "scope": "realtime",
        "iat": int(datetime.now(UTC).timestamp()),
        "exp": datetime.now(UTC) + timedelta(seconds=60),
    }
    assert pyjwt.decode(jose_jwt.encode(ticket, KEY, algorithm=ALG), KEY, algorithms=[ALG])["scope"] == "realtime"
    assert jose_jwt.decode(pyjwt.encode(ticket, KEY, algorithm=ALG), KEY, algorithms=[ALG])["scope"] == "realtime"


# ── PyJWT must refuse what python-jose refused (these always run) ──────────────────────────────────────────────────────────
def test_an_expired_token_is_refused_with_an_error_the_callers_catch():
    token = pyjwt.encode(_claims(exp=datetime.now(UTC) - timedelta(seconds=5)), KEY, algorithm=ALG)
    with pytest.raises(pyjwt.PyJWTError):
        pyjwt.decode(token, KEY, algorithms=[ALG])
    with pytest.raises(pyjwt.ExpiredSignatureError):
        pyjwt.decode(token, KEY, algorithms=[ALG])


def test_a_wrong_signature_a_wrong_key_and_garbage_are_all_pyjwt_errors():
    token = pyjwt.encode(_claims(), KEY, algorithm=ALG)
    for bad_token, key in ((token, "z" * 48), (token[:-4] + "AAAA", KEY), ("not-a-jwt", KEY), ("", KEY), ("a.b.c", KEY)):
        with pytest.raises(pyjwt.PyJWTError):
            pyjwt.decode(bad_token, key, algorithms=[ALG])


def test_an_alg_none_token_and_an_algorithm_the_server_did_not_allow_are_refused():
    forged = pyjwt.encode(_claims(), None, algorithm="none")
    with pytest.raises(pyjwt.PyJWTError):
        pyjwt.decode(forged, KEY, algorithms=[ALG])
    hs512 = pyjwt.encode(_claims(), KEY, algorithm="HS512")
    with pytest.raises(pyjwt.PyJWTError):
        pyjwt.decode(hs512, KEY, algorithms=[ALG])


def test_every_pyjwt_decode_failure_is_a_subclass_of_the_one_exception_the_callers_catch():
    """deps.py and graph_ws.py catch a single exception type around decode_token; it must cover every way decoding can fail."""
    for name in (
        "ExpiredSignatureError",
        "InvalidSignatureError",
        "DecodeError",
        "InvalidAlgorithmError",
        "InvalidTokenError",
        "ImmatureSignatureError",
        "InvalidAudienceError",
        "MissingRequiredClaimError",
    ):
        assert issubclass(getattr(pyjwt, name), pyjwt.PyJWTError), name


def test_a_non_string_subject_is_what_newer_pyjwt_refuses_so_the_apps_str_user_id_matters():
    """PyJWT 2.10+ rejects a non-string `sub`; the app always mints str(user.id), which is why the migration is safe. On older PyJWT this
    is accepted, so only the newer behaviour is asserted."""
    token = pyjwt.encode(_claims(sub=12345), KEY, algorithm=ALG)
    try:
        pyjwt.decode(token, KEY, algorithms=[ALG])
    except pyjwt.PyJWTError:
        return  # newer PyJWT: refused, as expected
    pytest.skip(f"PyJWT {pyjwt.__version__} does not validate the subject type (introduced in 2.10)")
