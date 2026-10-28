"""Fail-closed tests for DPoP sender-constrained tokens at the RS (#478, R.2).

A DPoP-bound access token (``cnf.jkt``, RFC 9449 §6.1) is only as safe as the
resource server's check: without it a stolen token is a bearer token. Each test
fails if the control is reverted, on the discovery path a deployed RS uses:

* a bound token presented as ``Bearer`` is refused (§7.1);
* a proof from any key but the bound one is refused (§6.1);
* a captured proof cannot be replayed (§11.1);
* ``required_binding=DPOP`` refuses an unbound token;
* ``build_resolved_config`` keeps the binding settings.
"""

from __future__ import annotations

import httpx
import pytest
import respx

from py_identity_model.core.dpop import create_dpop_proof, generate_dpop_key
from py_identity_model.core.dpop_verify import (
    DPoPErrorKind,
    DPoPValidationError,
    DPoPVerificationOptions,
    InMemoryDPoPReplayCache,
)
from py_identity_model.core.models import TokenValidationConfig
from py_identity_model.core.token_binding import (
    AuthorizationScheme,
    TokenBinding,
    TokenPresentation,
)
from py_identity_model.core.token_validation_logic import build_resolved_config
from py_identity_model.sync.token_validation import (
    clear_discovery_cache,
    clear_jwks_cache,
    validate_token,
)

from ._security_helpers import generate_rsa_keypair, sign_jwt


pytestmark = pytest.mark.unit

ISSUER = "https://op.example.com"
DISCO_URL = f"{ISSUER}/.well-known/openid-configuration"
AUDIENCE = "urn:api"
RS_URL = "https://rs.example.com/orders"


@pytest.fixture(autouse=True)
def _clear_caches():
    clear_discovery_cache()
    clear_jwks_cache()
    yield
    clear_discovery_cache()
    clear_jwks_cache()


@pytest.fixture
def op():
    """A mocked OP; returns a function minting tokens it signs."""
    key_dict, pem = generate_rsa_keypair()
    disco = {
        "issuer": ISSUER,
        "jwks_uri": f"{ISSUER}/jwks",
        "authorization_endpoint": f"{ISSUER}/authorize",
        "token_endpoint": f"{ISSUER}/token",
        "response_types_supported": ["code"],
        "subject_types_supported": ["public"],
        "id_token_signing_alg_values_supported": ["RS256"],
    }
    with respx.mock:
        respx.get(DISCO_URL).mock(return_value=httpx.Response(200, json=disco))
        respx.get(f"{ISSUER}/jwks").mock(
            return_value=httpx.Response(200, json={"keys": [key_dict]})
        )

        def mint(cnf: dict | None = None) -> str:
            claims: dict[str, object] = {"sub": "user", "iss": ISSUER, "aud": AUDIENCE}
            if cnf is not None:
                claims["cnf"] = cnf
            return sign_jwt(pem, claims, headers={"kid": key_dict["kid"]})

        yield mint


def _config(binding: TokenBinding = TokenBinding.NONE) -> TokenValidationConfig:
    return TokenValidationConfig(
        perform_disco=True,
        audience=AUDIENCE,
        required_binding=binding,
        dpop=DPoPVerificationOptions(replay_cache=InMemoryDPoPReplayCache()),
    )


def _rejected(token, config, presentation) -> DPoPErrorKind:
    with pytest.raises(DPoPValidationError) as exc:
        validate_token(token, config, DISCO_URL, presentation=presentation)
    return exc.value.kind


def _dpop(token, key) -> TokenPresentation:
    return TokenPresentation(
        scheme=AuthorizationScheme.DPOP,
        method="GET",
        url=RS_URL,
        dpop_proof=create_dpop_proof(key, "GET", RS_URL, access_token=token),
    )


def test_bound_token_accepted_with_its_key(op):
    key = generate_dpop_key()
    token = op({"jkt": key.jwk_thumbprint})

    claims = validate_token(token, _config(), DISCO_URL, presentation=_dpop(token, key))

    assert claims["cnf"] == {"jkt": key.jwk_thumbprint}


def test_stolen_token_as_bearer_refused(op):
    key = generate_dpop_key()
    token = op({"jkt": key.jwk_thumbprint})
    bearer = TokenPresentation(
        scheme=AuthorizationScheme.BEARER, method="GET", url=RS_URL
    )

    assert _rejected(token, _config(), bearer) is DPoPErrorKind.WRONG_SCHEME


def test_stolen_token_with_attacker_proof_refused(op):
    key = generate_dpop_key()
    token = op({"jkt": key.jwk_thumbprint})

    assert (
        _rejected(token, _config(), _dpop(token, generate_dpop_key()))
        is DPoPErrorKind.JKT_MISMATCH
    )


def test_captured_proof_replay_refused(op):
    key = generate_dpop_key()
    token = op({"jkt": key.jwk_thumbprint})
    config = _config()
    captured = _dpop(token, key)
    validate_token(token, config, DISCO_URL, presentation=captured)

    assert _rejected(token, config, captured) is DPoPErrorKind.REPLAYED_JTI


def test_required_dpop_refuses_unbound_token(op):
    token = op()
    bearer = TokenPresentation(
        scheme=AuthorizationScheme.BEARER, method="GET", url=RS_URL
    )

    assert _rejected(token, _config(TokenBinding.DPOP), bearer) is (
        DPoPErrorKind.NOT_BOUND
    )


def test_resolved_config_keeps_binding_settings():
    options = DPoPVerificationOptions(max_age=5)
    original = TokenValidationConfig(
        perform_disco=True, required_binding=TokenBinding.DPOP, dpop=options
    )

    resolved = build_resolved_config(original, {"kty": "RSA"}, "RS256")

    assert (resolved.required_binding, resolved.dpop) == (TokenBinding.DPOP, options)
