"""Tests for the FAPI 2.0 RP conformance harness (#475).

Covers the FAPI2-specific wiring added to the harness:
- ``GET /fapi2-jwks`` exposes only public key material (private_key_jwt JWKS),
- ``GET /authorize?fapi2=true`` drives PAR + PKCE S256 + private_key_jwt +
  DPoP and redirects with only ``client_id`` + ``request_uri`` (RFC 9126 §4),
- a missing PAR endpoint is rejected,
- ``ConformanceSuiteClient.create_plan`` merges the FAPI2 client overrides
  (registered JWKS + ``token_endpoint_auth_method=private_key_jwt``).

respx intercepts the harness's outbound httpx calls (discovery + PAR); the
suite-side plan creation is mocked at ``/api/plan``.
"""

from __future__ import annotations

import json

import app as harness_app
from fastapi.testclient import TestClient
import httpx
import jwt as pyjwt
import respx
from run_tests import ConformanceSuiteClient

from py_identity_model import generate_dpop_key, parse_authorize_callback_response


ISSUER = "https://op.example.com"
DISCO = {
    "issuer": ISSUER,
    "jwks_uri": f"{ISSUER}/jwks",
    "authorization_endpoint": f"{ISSUER}/auth",
    "token_endpoint": f"{ISSUER}/token",
    "pushed_authorization_request_endpoint": f"{ISSUER}/par",
    "response_types_supported": ["code"],
    "subject_types_supported": ["public"],
    "id_token_signing_alg_values_supported": ["ES256"],
    "authorization_response_iss_parameter_supported": True,
}


def _client() -> TestClient:
    return TestClient(harness_app.app)


def _mock_disco(mock: respx.MockRouter, disco: dict) -> None:
    for suffix in ("openid-configuration", "openid_configuration"):
        mock.get(f"{ISSUER}/.well-known/{suffix}").mock(
            return_value=httpx.Response(200, json=disco)
        )


# ---------------------------------------------------------------------------
# /fapi2-jwks
# ---------------------------------------------------------------------------


def test_fapi2_jwks_exposes_only_public_material() -> None:
    resp = _client().get("/fapi2-jwks")
    assert resp.status_code == httpx.codes.OK
    keys = resp.json()["keys"]
    assert len(keys) == 1
    jwk = keys[0]
    assert jwk["kty"] == "EC"
    assert jwk["alg"] == "ES256"
    assert jwk["use"] == "sig"
    assert jwk["kid"]
    # Public JWK must NOT carry the EC private scalar.
    assert "d" not in jwk


# ---------------------------------------------------------------------------
# /authorize?fapi2=true
# ---------------------------------------------------------------------------


@respx.mock
def test_fapi2_authorize_pushes_par_with_dpop_and_private_key_jwt() -> None:
    _mock_disco(respx.mock, DISCO)
    par_route = respx.post(f"{ISSUER}/par").mock(
        return_value=httpx.Response(
            201,
            json={
                "request_uri": "urn:ietf:params:oauth:request_uri:abc",
                "expires_in": 60,
            },
        )
    )

    resp = _client().get(
        "/authorize",
        params={"issuer": ISSUER, "client_id": "conformance-rp", "fapi2": "true"},
        follow_redirects=False,
    )

    assert resp.status_code == httpx.codes.FOUND
    location = resp.headers["location"]
    # RFC 9126 §4: only client_id + request_uri on the front channel.
    assert location.startswith(f"{ISSUER}/auth?")
    assert "client_id=conformance-rp" in location
    assert "request_uri=urn" in location
    assert "redirect_uri=" not in location
    assert "scope=" not in location

    par_req = par_route.calls.last.request
    body = par_req.content.decode()
    assert "client_assertion=" in body  # private_key_jwt
    assert "client_assertion_type=" in body
    assert "code_challenge=" in body
    assert "code_challenge_method=S256" in body
    # Token/PAR-endpoint DPoP proof: present, bound to POST + PAR URL, no ath.
    proof = par_req.headers["DPoP"]
    claims = pyjwt.decode(proof, options={"verify_signature": False})
    assert claims["htm"] == "POST"
    assert claims["htu"] == f"{ISSUER}/par"
    assert "ath" not in claims


@respx.mock
def test_fapi2_authorize_rejects_op_without_par_endpoint() -> None:
    disco_no_par = dict(DISCO)
    del disco_no_par["pushed_authorization_request_endpoint"]
    _mock_disco(respx.mock, disco_no_par)

    resp = _client().get(
        "/authorize",
        params={
            "issuer": ISSUER,
            "client_id": "conformance-rp",
            "fapi2": "true",
            "test_id": "t-no-par",
        },
        follow_redirects=False,
    )

    assert resp.status_code == httpx.codes.BAD_REQUEST
    assert resp.json()["error"] == "par_not_supported"


# ---------------------------------------------------------------------------
# create_plan client overrides (FAPI2 private_key_jwt registration)
# ---------------------------------------------------------------------------


@respx.mock
def test_create_plan_merges_fapi2_client_overrides() -> None:
    suite_url = "https://localhost.emobix.co.uk:8443"
    route = respx.post(f"{suite_url}/api/plan").mock(
        return_value=httpx.Response(200, json={"id": "plan-1", "modules": []})
    )
    suite = ConformanceSuiteClient(suite_url, token=None)

    jwks = {"keys": [{"kty": "EC", "kid": "k1", "crv": "P-256", "x": "x", "y": "y"}]}
    suite.create_plan(
        "fapi2-security-profile-final-client-test-plan",
        {"client_auth_type": "private_key_jwt"},
        "py-identity-model-fapi2-rp",
        client_overrides={
            "jwks": jwks,
            "token_endpoint_auth_method": "private_key_jwt",
        },
    )

    sent = json.loads(route.calls.last.request.content.decode())
    assert sent["client"]["jwks"] == jwks
    assert sent["client"]["token_endpoint_auth_method"] == "private_key_jwt"
    # The default client_secret path is untouched for non-FAPI2 plans.
    assert sent["client"]["client_id"] == "conformance-rp"


# ---------------------------------------------------------------------------
# callback helpers (RFC 9207 iss + token-request construction)
# ---------------------------------------------------------------------------


class _Disco:
    issuer = ISSUER
    token_endpoint = f"{ISSUER}/token"


def _fapi2_session() -> harness_app.AuthSession:
    return harness_app.AuthSession(
        issuer=ISSUER,
        state="s",
        nonce="n",
        client_id="conformance-rp",
        redirect_uri="https://rp.example.com/callback",
        code_verifier="cv",
        fapi2=True,
        dpop_key=generate_dpop_key("ES256"),
    )


def test_fapi2_iss_validation_accepts_matching_issuer() -> None:
    cb = parse_authorize_callback_response(
        f"https://rp.example.com/callback?code=c&state=s&iss={ISSUER}"
    )
    result = harness_app._validate_fapi2_callback_issuer(cb, _Disco(), _fapi2_session())
    assert result is None


def test_fapi2_iss_validation_rejects_missing_issuer() -> None:
    # FAPI 2.0 requires iss; a callback without it must be rejected.
    cb = parse_authorize_callback_response(
        "https://rp.example.com/callback?code=c&state=s"
    )
    session = _fapi2_session()
    result = harness_app._validate_fapi2_callback_issuer(cb, _Disco(), session)
    assert result is not None
    assert result.status_code == httpx.codes.BAD_REQUEST
    assert session.result["status"] == "error"


def test_non_fapi2_session_skips_iss_validation() -> None:
    cb = parse_authorize_callback_response(
        "https://rp.example.com/callback?code=c&state=s"
    )
    session = harness_app.AuthSession(issuer=ISSUER, state="s", nonce="n")
    assert harness_app._validate_fapi2_callback_issuer(cb, _Disco(), session) is None


def test_build_token_request_fapi2_uses_private_key_jwt_and_dpop() -> None:
    session = _fapi2_session()
    req = harness_app._build_auth_code_token_request(session, _Disco(), "the-code")
    assert req.private_key_jwt is not None
    assert req.dpop_key is session.dpop_key
    assert req.client_secret is None


def test_build_token_request_non_fapi2_uses_client_secret() -> None:
    session = harness_app.AuthSession(
        issuer=ISSUER,
        state="s",
        nonce="n",
        client_id="conformance-rp",
        client_secret="sekret",
        redirect_uri="https://rp.example.com/callback",
    )
    req = harness_app._build_auth_code_token_request(session, _Disco(), "the-code")
    assert req.private_key_jwt is None
    assert req.dpop_key is None
    assert req.client_secret == "sekret"
