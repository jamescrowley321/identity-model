"""Resource-server check of a live DPoP-bound opaque token's introspected ``cnf``.

The provider issues an opaque access token bound to the client's DPoP key and
reports the binding in its introspection response (``cnf.jkt``, RFC 9449 §6.2).
``check_introspection_binding`` then plays the resource server: the token is
rejected as a bearer token (§7.2) and accepted only with a proof signed by the
bound key for this token (§7.1).
"""

from __future__ import annotations

import httpx
import pytest

from py_identity_model import (
    AuthorizationScheme,
    DPoPErrorKind,
    DPoPValidationError,
    DPoPVerificationOptions,
    InMemoryDPoPReplayCache,
    IntrospectedTokenError,
    IntrospectedTokenErrorKind,
    TokenIntrospectionRequest,
    TokenPresentation,
    check_introspection_binding,
    create_dpop_proof,
    generate_dpop_key,
    introspect_token,
)
from py_identity_model.aio import (
    check_introspection_binding as acheck_introspection_binding,
)
from py_identity_model.aio import introspect_token as aintrospect_token


pytestmark = pytest.mark.integration

HTTP_OK = 200
RS_URL = "https://rs.example.com/api/orders"
METHOD = "GET"


@pytest.fixture(scope="module")
def opaque_client(provider_capabilities, raw_discovery, test_config):
    if "dpop" not in provider_capabilities:
        pytest.skip("Provider does not support DPoP")
    if "introspection" not in provider_capabilities:
        pytest.skip("Provider does not expose introspection_endpoint")
    client_id = test_config.get("TEST_OPAQUE_CLIENT_ID")
    client_secret = test_config.get("TEST_OPAQUE_CLIENT_SECRET")
    if not client_id or not client_secret:
        pytest.skip("TEST_OPAQUE_CLIENT_ID not configured")
    return {
        "token_endpoint": raw_discovery["token_endpoint"],
        "introspection_endpoint": raw_discovery["introspection_endpoint"],
        "client_id": client_id,
        "client_secret": client_secret,
        "scope": test_config.get("TEST_SCOPE", "openid"),
    }


def _opaque_token(client, key=None) -> str:
    """A client-credentials opaque token, DPoP-bound to *key* when given."""
    headers = {}
    if key is not None:
        headers["DPoP"] = create_dpop_proof(key, "POST", client["token_endpoint"])
    resp = httpx.post(
        client["token_endpoint"],
        data={"grant_type": "client_credentials", "scope": client["scope"]},
        auth=(client["client_id"], client["client_secret"]),
        headers=headers,
        timeout=10.0,
    )
    assert resp.status_code == HTTP_OK, resp.text
    return resp.json()["access_token"]


def _introspection_request(client, token) -> TokenIntrospectionRequest:
    return TokenIntrospectionRequest(
        address=client["introspection_endpoint"],
        token=token,
        client_id=client["client_id"],
        client_secret=client["client_secret"],
        token_type_hint="access_token",
    )


@pytest.fixture(scope="module")
def bound(opaque_client):
    """A live DPoP-bound opaque token, its key, and its introspection response."""
    key = generate_dpop_key()
    token = _opaque_token(opaque_client, key)
    response = introspect_token(_introspection_request(opaque_client, token))
    assert response.is_successful, response.error
    assert response.claims is not None
    assert response.claims["active"] is True
    assert response.claims["cnf"] == {"jkt": key.jwk_thumbprint}
    return key, token, response


def _dpop(key, token) -> TokenPresentation:
    return TokenPresentation(
        scheme=AuthorizationScheme.DPOP,
        method=METHOD,
        url=RS_URL,
        dpop_proof=create_dpop_proof(key, METHOD, RS_URL, access_token=token),
    )


def _options() -> DPoPVerificationOptions:
    return DPoPVerificationOptions(replay_cache=InMemoryDPoPReplayCache())


def test_bound_opaque_token_without_presentation_rejected(bound):
    _, token, response = bound

    with pytest.raises(DPoPValidationError) as exc:
        check_introspection_binding(response, token, None, dpop=_options())

    assert exc.value.kind is DPoPErrorKind.PROOF_REQUIRED


def test_bound_opaque_token_as_bearer_rejected(bound):
    _, token, response = bound
    presentation = TokenPresentation(scheme=AuthorizationScheme.BEARER)

    with pytest.raises(DPoPValidationError) as exc:
        check_introspection_binding(response, token, presentation, dpop=_options())

    assert exc.value.kind is DPoPErrorKind.WRONG_SCHEME


def test_bound_opaque_token_with_proof_accepted(bound):
    key, token, response = bound

    check_introspection_binding(response, token, _dpop(key, token), dpop=_options())


def test_bound_opaque_token_proof_from_other_key_rejected(bound):
    _, token, response = bound

    with pytest.raises(DPoPValidationError) as exc:
        check_introspection_binding(
            response, token, _dpop(generate_dpop_key(), token), dpop=_options()
        )

    assert exc.value.kind is DPoPErrorKind.JKT_MISMATCH


async def test_async_bound_opaque_token(opaque_client):
    key = generate_dpop_key()
    token = _opaque_token(opaque_client, key)
    response = await aintrospect_token(_introspection_request(opaque_client, token))
    assert response.is_successful, response.error

    with pytest.raises(DPoPValidationError) as exc:
        await acheck_introspection_binding(response, token, None, dpop=_options())
    assert exc.value.kind is DPoPErrorKind.PROOF_REQUIRED
    await acheck_introspection_binding(
        response, token, _dpop(key, token), dpop=_options()
    )


def test_unbound_opaque_token_without_presentation_accepted(opaque_client):
    token = _opaque_token(opaque_client)
    response = introspect_token(_introspection_request(opaque_client, token))
    assert response.is_successful, response.error
    assert response.claims is not None
    assert response.claims["active"] is True
    assert "cnf" not in response.claims

    check_introspection_binding(response, token, None)


def test_inactive_opaque_token_rejected(opaque_client):
    token = "not-an-issued-token"
    response = introspect_token(_introspection_request(opaque_client, token))
    assert response.is_successful, response.error
    assert response.claims is not None
    assert response.claims["active"] is False

    with pytest.raises(IntrospectedTokenError) as exc:
        check_introspection_binding(response, token, None)

    assert exc.value.kind is IntrospectedTokenErrorKind.INACTIVE
