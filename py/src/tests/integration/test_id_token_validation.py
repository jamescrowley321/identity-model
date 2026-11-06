"""Real-IdP validation of ``validate_id_token`` (OIDC Core §3.1.3.7 / §3.3.2.11).

The unit + conformance suites drive ``validate_id_token_claims`` against
synthetic claim sets. This suite proves the full public entry point
``validate_id_token`` end-to-end against a *live* OpenID Provider: a genuine ID
Token is minted through a real authorization-code + PKCE flow, its signature is
verified against the OP's JWKS via live discovery, and the ID-Token profile
rules are then enforced on the real claims.

Runs against whichever OP ``--env-file`` selects (the CI provider matrix). The
credential-free ``node-oidc-provider`` fixture (``make
test-integration-node-oidc``) supports the automated devInteractions flow, so
the base-profile and nonce/auth_time cases execute there rather than skip. The
``at_hash`` binding is asserted only when the OP actually mints an ``at_hash``
in its code-flow ID Token (node-oidc-provider, like most OPs, emits ``at_hash``
only for authorization-endpoint responses, i.e. the implicit/hybrid flows), so
that leg guards itself and documents the reason when the claim is absent.
"""

from __future__ import annotations

import jwt as pyjwt
import pytest

from py_identity_model import (
    TokenValidationConfig,
    validate_id_token,
)
from py_identity_model.exceptions import (
    IdTokenValidationException,
    TokenValidationException,
)

from .conftest import AuthCodeFlowConfig, perform_auth_code_flow


pytestmark = pytest.mark.integration

# A fixed nonce/max_age sent on the authorization request so the OP echoes a
# ``nonce`` and an ``auth_time`` into the minted ID Token, letting the live
# suite exercise the §3.1.3.7 nonce (step 11) and max_age/auth_time (step 12)
# bindings on a real token.
_LIVE_NONCE = "live-id-token-nonce-9f83c1"
_LIVE_MAX_AGE = 3600


def _decode_unverified(id_token: str) -> dict:
    """Read an ID Token's claims WITHOUT verifying — only to branch on presence."""
    return pyjwt.decode(id_token, options={"verify_signature": False})


def _require_auth_code(
    provider_capabilities, test_config
) -> tuple[str, str, str | None]:
    """Skip cleanly unless the selected OP can run the automated auth-code flow."""
    if "dev_interactions" not in provider_capabilities:
        pytest.skip(
            "Provider does not support automated auth code flow (no devInteractions)"
        )
    if "authorization_code" not in provider_capabilities:
        pytest.skip("Provider does not advertise authorization_endpoint")
    client_id = test_config.get("TEST_AUTH_CODE_CLIENT_ID")
    redirect_uri = test_config.get("TEST_AUTH_CODE_REDIRECT_URI")
    if not client_id or not redirect_uri:
        pytest.skip("TEST_AUTH_CODE_CLIENT_ID and TEST_AUTH_CODE_REDIRECT_URI required")
    return client_id, redirect_uri, test_config.get("TEST_AUTH_CODE_CLIENT_SECRET")


@pytest.fixture(scope="session")
def id_token_flow(provider_capabilities, discovery_document, test_config):
    """A real auth-code + PKCE flow that requests a nonce and a max_age.

    Returns the flow result plus the exact ``nonce``/``max_age`` sent, so the
    tests can assert the live ID Token binds to them.
    """
    client_id, redirect_uri, client_secret = _require_auth_code(
        provider_capabilities, test_config
    )
    result = perform_auth_code_flow(
        discovery=discovery_document,
        client_id=client_id,
        redirect_uri=redirect_uri,
        config=AuthCodeFlowConfig(
            client_secret=client_secret,
            scope="openid profile email offline_access",
            resource="urn:test:api",
            nonce=_LIVE_NONCE,
            max_age=_LIVE_MAX_AGE,
        ),
    )
    token = result["token_response"].token or {}
    id_token = token.get("id_token")
    if not id_token:
        pytest.skip(
            "Auth-code token response carried no id_token (openid scope not honoured)"
        )
    return {
        "id_token": id_token,
        "access_token": token.get("access_token"),
        "client_id": client_id,
        "nonce": _LIVE_NONCE,
        "max_age": _LIVE_MAX_AGE,
    }


def _config_for(
    client_id: str, issuer: str, require_https: bool
) -> TokenValidationConfig:
    """A discovery-driven validation config bound to the RP's client_id.

    ``audience`` is the RP's ``client_id`` and no ``verify_aud``-disabling
    options are supplied, so the standard path enforces the ``aud`` check (an ID
    Token MUST be audienced to the RP) and makes ``client_id`` the trusted
    audience of the ID-Token profile.
    """
    return TokenValidationConfig(
        perform_disco=True,
        audience=client_id,
        issuer=issuer,
        require_https=require_https,
    )


class TestValidateIdTokenLive:
    """End-to-end ``validate_id_token`` against a live OP."""

    def test_base_profile_validates(
        self, id_token_flow, test_config, issuer, require_https
    ):
        """A genuine ID Token passes signature + iss/aud/exp + the ID-Token profile."""
        config = _config_for(id_token_flow["client_id"], issuer, require_https)

        claims = validate_id_token(
            id_token_flow["id_token"],
            config,
            disco_doc_address=test_config["TEST_DISCO_ADDRESS"],
        )

        # Signature/iss/aud/exp are enforced inside validate_id_token; assert the
        # ID-Token profile essentials came back on the real claim set.
        assert claims["sub"], "validated ID Token is missing the required sub claim"
        assert claims["iss"] == issuer
        audiences = (
            claims["aud"] if isinstance(claims["aud"], list) else [claims["aud"]]
        )
        assert id_token_flow["client_id"] in audiences
        assert claims["exp"] > claims["iat"]

    def test_wrong_audience_is_rejected(
        self, id_token_flow, test_config, issuer, require_https
    ):
        """The same real ID Token fails when validated for a different client_id."""
        config = _config_for("some-other-audience", issuer, require_https)

        with pytest.raises(TokenValidationException):
            validate_id_token(
                id_token_flow["id_token"],
                config,
                disco_doc_address=test_config["TEST_DISCO_ADDRESS"],
            )

    def test_nonce_binding(self, id_token_flow, test_config, issuer, require_https):
        """The live ID Token binds to the nonce sent on the authorization request."""
        id_token = id_token_flow["id_token"]
        if "nonce" not in _decode_unverified(id_token):
            pytest.skip("OP did not echo the requested nonce into the ID Token")
        config = _config_for(id_token_flow["client_id"], issuer, require_https)

        # Matching nonce passes.
        claims = validate_id_token(
            id_token,
            config,
            disco_doc_address=test_config["TEST_DISCO_ADDRESS"],
            nonce=id_token_flow["nonce"],
        )
        assert claims["nonce"] == id_token_flow["nonce"]

        # A different nonce is rejected by the profile check.
        with pytest.raises(IdTokenValidationException):
            validate_id_token(
                id_token,
                config,
                disco_doc_address=test_config["TEST_DISCO_ADDRESS"],
                nonce="not-the-nonce-we-sent",
            )

    def test_max_age_auth_time(self, id_token_flow, test_config, issuer, require_https):
        """max_age/auth_time freshness is enforced on the real auth_time claim."""
        id_token = id_token_flow["id_token"]
        if "auth_time" not in _decode_unverified(id_token):
            pytest.skip(
                "OP did not include auth_time in the ID Token for the requested max_age"
            )
        config = _config_for(id_token_flow["client_id"], issuer, require_https)

        # A generous max_age accepts a just-minted token whose auth_time is now.
        claims = validate_id_token(
            id_token,
            config,
            disco_doc_address=test_config["TEST_DISCO_ADDRESS"],
            max_age=id_token_flow["max_age"],
        )
        assert isinstance(claims["auth_time"], int)

    def test_at_hash_binding_for_token_endpoint_id_token(
        self, id_token_flow, test_config, issuer, require_https
    ):
        """A code-flow (token-endpoint) ID Token binds at_hash only if present.

        §3.1.3.6 makes at_hash OPTIONAL here, so the caller marks the access
        token as not issued with the ID Token: an OP that omits at_hash is then
        accepted, one that mints it must bind the issued access token. By
        default at_hash is REQUIRED (§3.2.2.10, §3.3.2.11).
        """
        id_token = id_token_flow["id_token"]
        access_token = id_token_flow["access_token"]
        assert access_token, "the code flow returned no access_token"
        config = _config_for(id_token_flow["client_id"], issuer, require_https)
        disco = test_config["TEST_DISCO_ADDRESS"]

        # The issued access token passes, with or without an at_hash.
        validate_id_token(
            id_token,
            config,
            disco_doc_address=disco,
            access_token=access_token,
            access_token_issued_with_id_token=False,
        )

        if "at_hash" in _decode_unverified(id_token):
            # A present at_hash must bind: a tampered access token is rejected,
            # and requiring presence changes nothing.
            with pytest.raises(
                IdTokenValidationException, match=r"'at_hash' claim does not match"
            ):
                validate_id_token(
                    id_token,
                    config,
                    disco_doc_address=disco,
                    access_token=access_token + "tampered",
                    access_token_issued_with_id_token=False,
                )
            validate_id_token(
                id_token, config, disco_doc_address=disco, access_token=access_token
            )
        else:
            # No at_hash: nothing binds, so only the default presence rule rejects.
            with pytest.raises(
                IdTokenValidationException, match=r"missing required 'at_hash'"
            ):
                validate_id_token(
                    id_token, config, disco_doc_address=disco, access_token=access_token
                )
