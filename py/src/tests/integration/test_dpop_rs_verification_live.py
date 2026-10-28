"""Resource-server DPoP verification of a live DPoP-bound access token.

The provider issues a JWT access token bound to the client's DPoP key
(``cnf.jkt``, RFC 9449 §6.1). ``validate_token`` with a ``TokenPresentation``
then plays the resource server (§7.1): the issue #478 matrix rows run against
the real token, so the provider's ``cnf.jkt`` and this library's thumbprint and
proof verification are checked against each other.
"""

from __future__ import annotations

from dataclasses import replace
import time

import jwt as pyjwt
import pytest

from py_identity_model import (
    AuthorizationScheme,
    DPoPErrorKind,
    DPoPValidationError,
    DPoPVerificationOptions,
    InMemoryDPoPReplayCache,
    TokenBinding,
    TokenPresentation,
    TokenValidationConfig,
    compute_ath,
    create_dpop_proof,
    generate_dpop_key,
    validate_token,
)
from py_identity_model.aio import validate_token as avalidate_token

from .conftest import AuthCodeFlowConfig, perform_auth_code_flow


# node-oidc issues JWT access tokens for this resource (infra/node-oidc-provider).
RESOURCE = "urn:test:api"
RS_URL = "https://rs.example.com/api/orders"
METHOD = "GET"
FAPI_DPOP_ALGORITHMS = ("ES256", "PS256", "EdDSA")
STALE_SECONDS = 3600


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
            resource=RESOURCE,
            dpop_key=key,
        ),
    )
    response = result["token_response"]
    assert response.is_successful, response.error
    assert response.token is not None
    return response.token["access_token"]


@pytest.fixture(scope="module", params=FAPI_DPOP_ALGORITHMS)
def bound(request, discovery_document, auth_code_client):
    """A live DPoP-bound access token and the key it is bound to."""
    key = generate_dpop_key(request.param)
    return key, _access_token(discovery_document, auth_code_client, key)


@pytest.fixture(scope="module")
def unbound_token(discovery_document, auth_code_client) -> str:
    """A live Bearer access token for the same resource."""
    return _access_token(discovery_document, auth_code_client)


@pytest.fixture
def config(issuer, require_https) -> TokenValidationConfig:
    return TokenValidationConfig(
        perform_disco=True,
        audience=RESOURCE,
        issuer=issuer,
        require_https=require_https,
        dpop=DPoPVerificationOptions(replay_cache=InMemoryDPoPReplayCache()),
    )


@pytest.fixture
def validate(test_config, config):
    def _validate(token, presentation=None, *, cfg=None):
        return validate_token(
            token,
            cfg or config,
            test_config["TEST_DISCO_ADDRESS"],
            presentation=presentation,
        )

    return _validate


def _dpop(token, key, *, proof_method=METHOD, proof_url=RS_URL, proof=None):
    """A ``GET RS_URL`` request carrying a proof made for *proof_method*/*proof_url*."""
    return TokenPresentation(
        scheme=AuthorizationScheme.DPOP,
        method=METHOD,
        url=RS_URL,
        dpop_proof=proof
        or create_dpop_proof(key, proof_method, proof_url, access_token=token),
    )


def _kind(validate, token, presentation, **kwargs) -> DPoPErrorKind:
    with pytest.raises(DPoPValidationError) as exc:
        validate(token, presentation, **kwargs)
    return exc.value.kind


def _signed_proof(key, token, *, typ="dpop+jwt", **claims) -> str:
    """A proof signed by *key* with overridden ``typ`` and payload claims."""
    payload = {
        "jti": f"live-{time.time_ns()}",
        "htm": METHOD,
        "htu": RS_URL,
        "iat": int(time.time()),
        "ath": compute_ath(token),
        **claims,
    }
    return pyjwt.encode(
        payload,
        key.private_key_pem,
        algorithm=key.algorithm,
        headers={"typ": typ, "jwk": key.public_jwk},
    )


@pytest.mark.integration
class TestDPoPBoundTokenLive:
    def test_1_valid_proof_accepted(self, validate, bound):
        key, token = bound

        claims = validate(token, _dpop(token, key))

        assert claims["cnf"]["jkt"] == key.jwk_thumbprint

    def test_1_required_dpop_accepted(self, validate, config, bound):
        key, token = bound
        cfg = replace(config, required_binding=TokenBinding.DPOP)

        assert validate(token, _dpop(token, key), cfg=cfg)["aud"] == RESOURCE

    async def test_1_async_valid_proof_accepted(self, test_config, config, bound):
        key, token = bound

        claims = await avalidate_token(
            token,
            config,
            test_config["TEST_DISCO_ADDRESS"],
            presentation=_dpop(token, key),
        )

        assert claims["cnf"]["jkt"] == key.jwk_thumbprint

    def test_2_other_key_rejected(self, validate, bound):
        _key, token = bound
        attacker = generate_dpop_key()

        assert _kind(validate, token, _dpop(token, attacker)) is (
            DPoPErrorKind.JKT_MISMATCH
        )

    def test_3_replayed_proof_rejected(self, validate, bound):
        key, token = bound
        presentation = _dpop(token, key)
        validate(token, presentation)

        assert _kind(validate, token, presentation) is DPoPErrorKind.REPLAYED_JTI

    def test_4_htu_mismatch_rejected(self, validate, bound):
        key, token = bound
        presentation = _dpop(token, key, proof_url="https://rs.example.com/api/other")

        assert _kind(validate, token, presentation) is DPoPErrorKind.HTU_MISMATCH

    def test_5_htm_mismatch_rejected(self, validate, bound):
        key, token = bound
        presentation = _dpop(token, key, proof_method="POST")

        assert _kind(validate, token, presentation) is DPoPErrorKind.HTM_MISMATCH

    @pytest.mark.parametrize("offset", [-STALE_SECONDS, STALE_SECONDS])
    def test_6_iat_outside_window_rejected(self, validate, bound, offset):
        key, token = bound
        proof = _signed_proof(key, token, iat=int(time.time()) + offset)

        assert _kind(validate, token, _dpop(token, key, proof=proof)) is (
            DPoPErrorKind.IAT_OUT_OF_WINDOW
        )

    def test_7_ath_mismatch_rejected(self, validate, bound, unbound_token):
        key, token = bound
        proof = _signed_proof(key, token, ath=compute_ath(unbound_token))

        assert _kind(validate, token, _dpop(token, key, proof=proof)) is (
            DPoPErrorKind.ATH_MISMATCH
        )

    def test_8_tampered_signature_rejected(self, validate, bound):
        key, token = bound
        header, payload, signature = create_dpop_proof(
            key, METHOD, RS_URL, access_token=token
        ).split(".")
        tampered = ("A" if signature[0] != "A" else "B") + signature[1:]
        proof = f"{header}.{payload}.{tampered}"

        assert _kind(validate, token, _dpop(token, key, proof=proof)) is (
            DPoPErrorKind.INVALID_SIGNATURE
        )

    def test_9_bound_token_as_bearer_rejected(self, validate, bound):
        _key, token = bound
        bearer = TokenPresentation(
            scheme=AuthorizationScheme.BEARER, method=METHOD, url=RS_URL
        )

        assert _kind(validate, token, bearer) is DPoPErrorKind.WRONG_SCHEME

    def test_11_typ_jwt_rejected(self, validate, bound):
        key, token = bound
        proof = _signed_proof(key, token, typ="JWT")

        assert _kind(validate, token, _dpop(token, key, proof=proof)) is (
            DPoPErrorKind.INVALID_TYPE
        )


@pytest.mark.integration
class TestUnboundTokenLive:
    def test_10_required_dpop_unbound_rejected(self, validate, config, unbound_token):
        cfg = replace(config, required_binding=TokenBinding.DPOP)
        bearer = TokenPresentation(
            scheme=AuthorizationScheme.BEARER, method=METHOD, url=RS_URL
        )

        assert _kind(validate, unbound_token, bearer, cfg=cfg) is (
            DPoPErrorKind.NOT_BOUND
        )

    def test_12_unbound_bearer_accepted(self, validate, unbound_token):
        bearer = TokenPresentation(
            scheme=AuthorizationScheme.BEARER, method=METHOD, url=RS_URL
        )

        claims = validate(unbound_token, bearer)

        assert "cnf" not in claims
        assert claims["aud"] == RESOURCE
