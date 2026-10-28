"""Live DPoP binding across the code exchange and the refresh grant.

RFC 9449 §5 / FAPI 2.0 Security Profile §5.3.3.1: the refresh request carries
a DPoP proof so the new access token stays bound; ``require_dpop_token_type``
refuses a response that comes back as a Bearer token.  Keys cover the FAPI 2.0
§5.4.1 algorithms the provider advertises (ES256, PS256, EdDSA).
"""

import pytest

from py_identity_model import (
    RefreshTokenRequest,
    TokenErrorKind,
    generate_dpop_key,
    refresh_token,
)

from .conftest import AuthCodeFlowConfig, perform_auth_code_flow


FAPI_DPOP_ALGORITHMS = ("ES256", "PS256", "EdDSA")
DPOP_TOKEN_TYPE = "DPoP"


@pytest.fixture
def dpop_auth_code_client(provider_capabilities, test_config):
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


def _dpop_bound_tokens(discovery, client, key) -> dict:
    result = perform_auth_code_flow(
        discovery=discovery,
        client_id=client["client_id"],
        redirect_uri=client["redirect_uri"],
        config=AuthCodeFlowConfig(client_secret=client["client_secret"], dpop_key=key),
    )
    token_response = result["token_response"]
    assert token_response.is_successful, token_response.error
    assert token_response.token["token_type"] == DPOP_TOKEN_TYPE
    assert "refresh_token" in token_response.token
    return token_response.token


@pytest.mark.integration
@pytest.mark.parametrize("algorithm", FAPI_DPOP_ALGORITHMS)
def test_refresh_keeps_dpop_binding(
    algorithm, discovery_document, dpop_auth_code_client
):
    advertised = discovery_document.dpop_signing_alg_values_supported or []
    if algorithm not in advertised:
        pytest.skip(f"Provider does not advertise DPoP {algorithm}")
    key = generate_dpop_key(algorithm)
    tokens = _dpop_bound_tokens(discovery_document, dpop_auth_code_client, key)

    response = refresh_token(
        RefreshTokenRequest(
            address=discovery_document.token_endpoint,
            client_id=dpop_auth_code_client["client_id"],
            client_secret=dpop_auth_code_client["client_secret"],
            refresh_token=tokens["refresh_token"],
            dpop_key=key,
            require_dpop_token_type=True,
        )
    )
    assert response.is_successful, response.error
    assert response.token is not None
    assert response.token["token_type"] == DPOP_TOKEN_TYPE


@pytest.mark.integration
def test_refresh_without_proof_is_a_refused_downgrade(
    discovery_document, dpop_auth_code_client
):
    """A refresh the server answers with Bearer fails when DPoP is required."""
    key = generate_dpop_key("ES256")
    tokens = _dpop_bound_tokens(discovery_document, dpop_auth_code_client, key)

    response = refresh_token(
        RefreshTokenRequest(
            address=discovery_document.token_endpoint,
            client_id=dpop_auth_code_client["client_id"],
            client_secret=dpop_auth_code_client["client_secret"],
            refresh_token=tokens["refresh_token"],
            require_dpop_token_type=True,
        )
    )
    assert response.is_successful is False
    assert response.error_kind is TokenErrorKind.DPOP_TOKEN_TYPE_MISMATCH
