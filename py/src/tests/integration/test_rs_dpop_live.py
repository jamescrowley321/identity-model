"""DPoP-bound tokens through the booted resource server (#1021, RFC 9449 §7.1).

node-oidc issues a JWT access token bound to the client's DPoP key; the RS
(``TokenValidationMiddleware`` under real uvicorn) must accept it only with the
``DPoP`` scheme and a fresh proof for the request, and challenge with
``WWW-Authenticate: DPoP`` otherwise.

Run via ``make test-harness-rs``; under plain ``make test-integration-node-oidc``
the fastapi stack is absent, so the module importorskips.
"""

import httpx
import pytest

from py_identity_model import (
    DPoPVerificationOptions,
    create_dpop_proof,
    generate_dpop_key,
)

from ..harness.rs_server import boot_rs
from .conftest import AuthCodeFlowConfig, perform_auth_code_flow


pytest.importorskip("fastapi_identity_model")

pytestmark = pytest.mark.integration

# node-oidc issues JWT access tokens for this resource (infra/node-oidc-provider).
RS_AUDIENCE = "urn:test:api"
ROUTE = "/whoami"
GENERIC_401 = {"detail": "Invalid or unauthorized token"}
ALGS = " ".join(DPoPVerificationOptions().accepted_algorithms)
INVALID_TOKEN = f'DPoP error="invalid_token", algs="{ALGS}"'
INVALID_PROOF = f'DPoP error="invalid_dpop_proof", algs="{ALGS}"'


@pytest.fixture(scope="module")
def auth_code_client(provider_capabilities, test_config):
    """Auth-code client settings, skipping a provider without DPoP or the flow."""
    if "dpop" not in provider_capabilities:
        pytest.skip("Provider does not support DPoP")
    if "dev_interactions" not in provider_capabilities:
        pytest.skip("Provider does not support automated auth code flow")
    client_id = test_config.get("TEST_AUTH_CODE_CLIENT_ID")
    redirect_uri = test_config.get("TEST_AUTH_CODE_REDIRECT_URI")
    if not client_id or not redirect_uri:
        pytest.skip("TEST_AUTH_CODE_CLIENT_ID and TEST_AUTH_CODE_REDIRECT_URI required")
    return {
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "client_secret": test_config.get("TEST_AUTH_CODE_CLIENT_SECRET"),
    }


def _access_token(discovery, client, key=None) -> str:
    result = perform_auth_code_flow(
        discovery=discovery,
        client_id=client["client_id"],
        redirect_uri=client["redirect_uri"],
        config=AuthCodeFlowConfig(
            client_secret=client["client_secret"],
            resource=RS_AUDIENCE,
            dpop_key=key,
        ),
    )
    response = result["token_response"]
    assert response.is_successful, response.error
    assert response.token is not None
    return response.token["access_token"]


@pytest.fixture(scope="module")
def bound(discovery_document, auth_code_client):
    """A live DPoP-bound access token and the key it is bound to."""
    key = generate_dpop_key()
    return key, _access_token(discovery_document, auth_code_client, key)


@pytest.fixture(scope="module")
def unbound_token(discovery_document, auth_code_client) -> str:
    return _access_token(discovery_document, auth_code_client)


@pytest.fixture(scope="module")
def rs(test_config):
    with boot_rs(
        discovery_url=test_config["TEST_DISCO_ADDRESS"], audience=RS_AUDIENCE
    ) as base_url:
        yield base_url


def _dpop_headers(base_url, token, key) -> dict[str, str]:
    return {
        "Authorization": f"DPoP {token}",
        "DPoP": create_dpop_proof(key, "GET", f"{base_url}{ROUTE}", access_token=token),
    }


def _get(base_url, headers=None) -> httpx.Response:
    return httpx.get(f"{base_url}{ROUTE}", headers=headers, timeout=10.0)


def _rejection(response: httpx.Response) -> tuple:
    return (
        response.status_code,
        response.headers.get("WWW-Authenticate"),
        response.json(),
    )


def test_valid_proof_accepted(rs, bound):
    key, token = bound

    response = _get(rs, _dpop_headers(rs, token, key))

    assert response.status_code == httpx.codes.OK


def test_bound_token_as_bearer_rejected(rs, bound):
    _key, token = bound

    response = _get(rs, {"Authorization": f"Bearer {token}"})

    assert _rejection(response) == (401, INVALID_TOKEN, GENERIC_401)


def test_proof_from_other_key_rejected(rs, bound):
    _key, token = bound

    response = _get(rs, _dpop_headers(rs, token, generate_dpop_key()))

    assert _rejection(response) == (401, INVALID_TOKEN, GENERIC_401)


def test_replayed_proof_rejected(rs, bound):
    key, token = bound
    headers = _dpop_headers(rs, token, key)

    first = _get(rs, headers)
    replay = _get(rs, headers)

    assert (first.status_code, _rejection(replay)) == (
        httpx.codes.OK,
        (401, INVALID_PROOF, GENERIC_401),
    )


def test_unbound_bearer_accepted_by_default(rs, unbound_token):
    response = _get(rs, {"Authorization": f"Bearer {unbound_token}"})

    assert response.status_code == httpx.codes.OK


def test_unbound_bearer_rejected_when_dpop_required(test_config, unbound_token):
    with boot_rs(
        discovery_url=test_config["TEST_DISCO_ADDRESS"],
        audience=RS_AUDIENCE,
        extra_env={"RS_REQUIRED_BINDING": "dpop"},
    ) as base_url:
        response = _get(base_url, {"Authorization": f"Bearer {unbound_token}"})

    assert _rejection(response) == (401, INVALID_TOKEN, GENERIC_401)
